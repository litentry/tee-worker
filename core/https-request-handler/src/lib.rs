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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use http_req_sgx as http_req;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use http_sgx as http;

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

use http::header::{AUTHORIZATION, CONNECTION};
use http_req::response::Headers;
use serde::{Deserialize, Serialize};
use std::{
	fmt::Debug,
	format, str,
	string::{String, ToString},
	sync::Arc,
	time::Duration,
	vec,
	vec::Vec,
};
use url::Url;

use ita_stf::Hash;
use itc_rest_client::{
	error::Error as HttpError,
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestPath,
};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_top_pool_author::traits::AuthorApi;
use litentry_primitives::{Identity, IdentityHandle, IdentityString, IdentityWebType};

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

pub mod web2_identity;

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

pub struct RequestContext<
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
	> RequestContext<K, A, S>
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
	RestClient::new(http_client, base_url)
}

pub fn build_client_with_authorization(
	base_url: String,
	authorization_token: Option<String>,
) -> RestClient<HttpClient<DefaultSend>> {
	let base_url = Url::parse(base_url.as_str()).unwrap();
	let mut headers = Headers::new();
	headers.insert(CONNECTION.as_str(), "close");
	if let Some(authorization_token) = authorization_token {
		headers.insert(AUTHORIZATION.as_str(), authorization_token.as_str());
	}
	build_client(base_url, headers)
}

pub trait DecryptionVerificationPayload<K: ShieldingCryptoDecrypt> {
	fn decrypt_ciphertext(&self, key: K) -> Result<VerificationPayload, Error>;
}

pub trait UserInfo {
	fn get_user_id(&self) -> Option<String>;
}

pub trait RequestHandler<
	K: ShieldingCryptoEncrypt + ShieldingCryptoDecrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
>
{
	type Response: Debug + serde::de::DeserializeOwned + RestPath<String>;
	// fn make_https_request(&self, context: &RequestContext<K,A,S>)->

	fn send_request(
		&self,
		verification_context: &RequestContext<K, A, S>,
		client: RestClient<HttpClient<DefaultSend>>,
		path: String,
	) -> Result<(), Error>;

	fn handle_response(
		&self,
		verification_context: &RequestContext<K, A, S>,
		response: Self::Response,
	) -> Result<(), Error>;
}
