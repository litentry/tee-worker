// Copyright 2020-2022 Litentry Technologies GmbH.
// This file is part of Litentry.
//
// Litentry is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Litentry is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Litentry.  If not, see <https://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use http_sgx as http;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use http_req_sgx as http_req;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
	pub use url_sgx as url;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use codec::Encode;
use http::header::{HeaderName, AUTHORIZATION, CONNECTION};
use http_req::{request::Method, response::Headers};
use ita_stf::{AccountId, Hash, KeyPair, TrustedCall, TrustedOperation};
use itc_rest_client::{
	error::Error as HttpError,
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath,
};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_top_pool_author::traits::AuthorApi;
use litentry_primitives::DID;
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, sr25519::Pair};
use std::{
	boxed::Box,
	format, str,
	string::{String, ToString},
	sync::Arc,
	time::Duration,
	vec,
	vec::Vec,
};
use url::Url;

const TIMEOUT: Duration = Duration::from_secs(3u64);

#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
	#[error("Request error: {0}")]
	RquestError(String),

	#[error("Other error: {0}")]
	OtherError(String),
}

pub fn build_client(
	base_url: Url,
	headers: Headers,
	// path: Vec<u8>,
	// query: Option<Vec<(Vec<u8>, Vec<u8>)>>,
) -> RestClient<HttpClient<DefaultSend>> {
	let http_client = HttpClient::new(DefaultSend {}, true, Some(TIMEOUT), Some(headers), None);
	RestClient::new(http_client, base_url.clone())
}

pub fn build_twitter_client(
	authorization_token: Option<String>,
) -> RestClient<HttpClient<DefaultSend>> {
	let base_url = Url::parse("https://api.twitter.com").unwrap();
	let mut headers = Headers::new();
	headers.insert(CONNECTION.as_str(), "close");
	if let Some(authorization_token) = authorization_token {
		headers.insert(AUTHORIZATION.as_str(), authorization_token.as_str());
	}
	build_client(base_url, headers)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TwitterResponse {
	pub data: Vec<Tweet>,
	pub includes: TweetExpansions,
}

impl RestPath<String> for TwitterResponse {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tweet {
	pub author_id: String,
	pub id: String,
	pub text: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TweetExpansions {
	pub users: Vec<TweetAuthor>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TweetAuthor {
	pub id: String,
	pub name: String,
	pub username: String,
}

pub trait RequestHandler {
	fn send_request(
		&self,
		target: AccountId,
		client: RestClient<HttpClient<DefaultSend>>,
		path: String,
		query: Option<Vec<(Vec<u8>, Vec<u8>)>>,
	) -> Result<(), Error>;
}

pub struct TwitterRequestHandler<K, A, S> {
	shard_identifier: sp_core::H256,
	shielding_key: K,
	enclave_signer: Arc<S>,
	author: Arc<A>,
}

impl<
		K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt,
		A: AuthorApi<Hash, Hash>,
		S: StfEnclaveSigning,
	> TwitterRequestHandler<K, A, S>
{
	pub fn new(
		shard_identifier: sp_core::H256,
		shielding_key: K,
		enclave_signer: Arc<S>,
		author: Arc<A>,
	) -> Self {
		Self { shard_identifier, shielding_key, enclave_signer, author }
	}

	pub fn response_handler(
		&self,
		target: AccountId,
		response: TwitterResponse,
	) -> Result<(), Error> {
		log::warn!("twitter:{:?}", response);
		// TODO decrypt && verify the tweet
		// Rsa3072Seal::unseal_from_static_file().unwrap().decrypt("XXX".as_bytes());

		let did = DID::try_from("did:twitter:web2:_:myTwitterHandle".as_bytes().to_vec())
			.map_err(|_| Error::OtherError("did format error".to_string()))?;

		let enclave_account_id = self
			.enclave_signer
			.get_enclave_account()
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;
		let trusted_call = TrustedCall::verify_identity(enclave_account_id, target, did);
		let signed_trusted_call = self
			.enclave_signer
			.sign_call_with_self(&trusted_call, &self.shard_identifier)
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;
		let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);
		let encrypted_trusted_call = self
			.shielding_key
			.encrypt(&trusted_operation.encode())
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

		// TODO should wait the extrinsic until it is already?
		self.author.submit_top(encrypted_trusted_call, self.shard_identifier);
		// self.author.submit_trusted_call(shard, encrypted_trusted_call);
		Ok(())
	}
}

impl<
		K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt,
		A: AuthorApi<Hash, Hash>,
		S: StfEnclaveSigning,
	> RequestHandler for TwitterRequestHandler<K, A, S>
{
	fn send_request(
		&self,
		target: AccountId,
		mut client: RestClient<HttpClient<DefaultSend>>,
		path: String,
		query: Option<Vec<(Vec<u8>, Vec<u8>)>>,
	) -> Result<(), Error> {
		let response: TwitterResponse;
		if let Some(query) = query {
			let query: Vec<(&str, &str)> = query
				.iter()
				.map(|(key, value)| {
					(
						str::from_utf8(key.as_slice()).unwrap(),
						str::from_utf8(value.as_slice()).unwrap(),
					)
				})
				.collect();
			response = client
				.get_with::<String, TwitterResponse>(path.to_string(), query.as_slice())
				.map_err(|e| Error::RquestError(format!("{:?}", e)))?;
		} else {
			response = client
				.get::<String, TwitterResponse>(path.to_string())
				.map_err(|e| Error::RquestError(format!("{:?}", e)))?;
		}
		self.response_handler(target, response).clone()
	}
}
