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
	pub use futures_sgx as futures;
	pub use hex_sgx as hex;
	pub use thiserror_sgx as thiserror;
	pub use url_sgx as url;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use codec::Encode;
use futures::executor;
use http::header::{HeaderName, AUTHORIZATION, CONNECTION};
use http_req::{request::Method, response::Headers};
use ita_stf::{helpers, AccountId, Hash, KeyPair, TrustedCall, TrustedOperation};
use itc_https_client_daemon::Request;
use itc_rest_client::{
	error::Error as HttpError,
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath,
};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_storage::StorageHasher;
use itp_top_pool_author::traits::AuthorApi;
use litentry_primitives::DID;
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, sr25519::Pair, ByteArray};
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

pub struct VerificationPayload {
	pub owner: String,
	pub code: u32,
	pub did: String,
}

pub fn build_client(base_url: Url, headers: Headers) -> RestClient<HttpClient<DefaultSend>> {
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
		client: RestClient<HttpClient<DefaultSend>>,
		request: Request,
		path: String,
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
		request: Request,
		response: TwitterResponse,
	) -> Result<(), Error> {
		log::warn!("twitter:{:?}", response);
		// TODO decrypt
		self.shielding_key.decrypt("xxxxx".as_bytes());

		// mock data
		let payload = VerificationPayload {
			owner: "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d".to_string(), // alice public key
			code: 1134,
			did: "did:twitter:web2:_:myTwitterHandle".to_string(),
		};
		let request_did = str::from_utf8(request.did.as_slice())
			.map_err(|_| Error::OtherError("did format error".to_string()))?;
		if !payload.did.eq(request_did) {
			return Err(Error::OtherError(format!("did is not the same ",)))
		}

		let target_hex = hex::encode(request.target.as_slice());
		if !payload.owner.eq_ignore_ascii_case(target_hex.as_str()) {
			return Err(Error::OtherError(format!(
				"owner is not the same as target:{:?}",
				target_hex
			)))
		}

		if !request.challenge_code.eq(&payload.code) {
			return Err(Error::OtherError(format!("challenge code is not the same ",)))
		}

		let enclave_account_id = self
			.enclave_signer
			.get_enclave_account()
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;
		let trusted_call =
			TrustedCall::verify_identity(enclave_account_id, request.target, request.did);
		let signed_trusted_call = self
			.enclave_signer
			.sign_call_with_self(&trusted_call, &self.shard_identifier)
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;
		let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);
		let encrypted_trusted_call = self
			.shielding_key
			.encrypt(&trusted_operation.encode())
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

		let top_submit_future =
			async { self.author.submit_top(encrypted_trusted_call, self.shard_identifier).await };
		executor::block_on(top_submit_future).map_err(|e| {
			Error::OtherError(format!("Error adding indirect trusted call to TOP pool: {:?}", e))
		})?;
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
		mut client: RestClient<HttpClient<DefaultSend>>,
		request: Request,
		path: String,
	) -> Result<(), Error> {
		let response: TwitterResponse;
		if let Some(ref query) = request.query {
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
		self.response_handler(request, response).clone()
	}
}
