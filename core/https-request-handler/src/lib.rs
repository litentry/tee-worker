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
use http::header::{AUTHORIZATION, CONNECTION};
use http_req::response::Headers;
use ita_stf::{Hash, TrustedCall, TrustedOperation};
use itc_https_client_daemon::Request;
use itc_rest_client::{
	error::Error as HttpError,
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath,
};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_top_pool_author::traits::AuthorApi;
use litentry_primitives::{
	Identity, IdentityHandle, IdentityString, IdentityWebType, TwitterValidationData, Web2Network,
	Web2ValidationData, Web2ValidationData::Twitter,
};
use serde::{Deserialize, Serialize};
use sp_core::ByteArray;
use std::{
	boxed::Box,
	fmt::Debug,
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
	pub identity: Identity,
}

pub struct VerificationContext<
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
> {
	shielding_key: K,
	shard_identifier: sp_core::H256,
	enclave_signer: Arc<S>,
	author: Arc<A>,
}

impl<
		K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
		A: AuthorApi<Hash, Hash>,
		S: StfEnclaveSigning,
	> VerificationContext<K, A, S>
{
	pub fn new(
		shard_identifier: sp_core::H256,
		shielding_key: K,
		enclave_signer: Arc<S>,
		author: Arc<A>,
	) -> Self {
		Self { shard_identifier, shielding_key, enclave_signer, author }
	}
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

pub trait DecryptionVerificationPayload<K: ShieldingCryptoDecrypt> {
	fn decrypt_ciphertext(&self, key: K) -> Result<VerificationPayload, ()>;
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

impl<K: ShieldingCryptoDecrypt> DecryptionVerificationPayload<K> for TwitterResponse {
	fn decrypt_ciphertext(&self, key: K) -> Result<VerificationPayload, ()> {
		// TODO decrypt
		if self.data.len() > 0 {
			key.decrypt(self.data.get(0).unwrap().text.as_bytes());
		}

		// mock data
		let payload = VerificationPayload {
			owner: "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d".to_string(), // alice public key
			code: 1134,
			//identiy json: {"web_type":{"Web2":"Twitter"},"handle":{"String":[108,105,116,101,110,116,114,121]}}
			identity: Identity {
				web_type: IdentityWebType::Web2(Web2Network::Twitter),
				handle: IdentityHandle::String(
					IdentityString::try_from("litentry".as_bytes().to_vec()).unwrap(),
				),
			},
		};
		Ok(payload)
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

pub trait RequestHandler<
	K: ShieldingCryptoEncrypt + ShieldingCryptoDecrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
>
{
	fn send_request<
		R: DecryptionVerificationPayload<K> + Debug + serde::de::DeserializeOwned + RestPath<String>,
	>(
		&self,
		verification_context: &VerificationContext<K, A, S>,
		mut client: RestClient<HttpClient<DefaultSend>>,
		request: Request,
		path: String,
	) -> Result<(), Error> {
		let query: Vec<(&str, &str)> = match request.validation_data {
			Web2ValidationData::Twitter(TwitterValidationData { ref tweet_id }) => {
				vec![
					("ids", str::from_utf8(tweet_id.as_slice()).unwrap()),
					("expansions", "author_id"),
				]
			},
			Web2ValidationData::Discord(_) => {
				//todo
				vec![]
			},
		};
		let response: R = client
			.get_with::<String, R>(path.to_string(), query.as_slice())
			.map_err(|e| Error::RquestError(format!("{:?}", e)))?;
		log::warn!("response:{:?}", response);

		let payload = response.decrypt_ciphertext(verification_context.shielding_key.clone());
		if let Ok(payload) = payload {
			return self.response_handler(&verification_context, request, payload).clone()
		}
		return Err(Error::OtherError("decrypt payload error".to_string()))
	}

	fn response_handler(
		&self,
		verification_context: &VerificationContext<K, A, S>,
		request: Request,
		payload: VerificationPayload,
	) -> Result<(), Error> {
		//TODO verify author

		if !payload.identity.eq(&request.identity) {
			return Err(Error::OtherError("identity is not the same".to_string()))
		}

		let target_hex = hex::encode(request.target.as_slice());
		if !payload.owner.eq_ignore_ascii_case(target_hex.as_str()) {
			return Err(Error::OtherError(format!(
				"owner is not the same as target:{:?}",
				target_hex
			)))
		}

		if !request.challenge_code.eq(&payload.code) {
			return Err(Error::OtherError("challenge code is not the same".to_string()))
		}

		let enclave_account_id = verification_context
			.enclave_signer
			.get_enclave_account()
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;
		let trusted_call =
			TrustedCall::verify_identity(enclave_account_id, request.target, request.identity);
		let signed_trusted_call = verification_context
			.enclave_signer
			.sign_call_with_self(&trusted_call, &verification_context.shard_identifier)
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;
		let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);
		let encrypted_trusted_call = verification_context
			.shielding_key
			.encrypt(&trusted_operation.encode())
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

		let top_submit_future = async {
			verification_context
				.author
				.submit_top(encrypted_trusted_call, verification_context.shard_identifier.clone())
				.await
		};
		executor::block_on(top_submit_future).map_err(|e| {
			Error::OtherError(format!("Error adding indirect trusted call to TOP pool: {:?}", e))
		})?;
		Ok(())
	}
}

pub struct CommonHandler {}

impl<
		A: AuthorApi<Hash, Hash>,
		S: StfEnclaveSigning,
		K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	> RequestHandler<K, A, S> for CommonHandler
{
}
