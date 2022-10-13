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

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{ensure, get_expected_payload};
use codec::{Decode, Encode};
use http::header::{AUTHORIZATION, CONNECTION};
use http_req::response::Headers;
use itc_rest_client::{
	error::Error as HttpError,
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath,
};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use lc_stf_task_sender::Web2IdentityVerificationRequest;
use litentry_primitives::{IdentityHandle, TwitterValidationData, Web2ValidationData};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
	fmt::Debug,
	format,
	marker::PhantomData,
	str,
	string::{String, ToString},
	time::Duration,
	vec,
	vec::Vec,
};
use url::Url;

pub mod discord;
pub mod twitter;

#[cfg(not(test))]
const TWITTER_BASE_URL: &str = "https://api.twitter.com";
#[cfg(not(test))]
const DISCORD_BASE_URL: &str = "https://discordapp.com";

#[cfg(test)]
const TWITTER_BASE_URL: &str = "http://localhost";
#[cfg(test)]
const DISCORD_BASE_URL: &str = "http://localhost";

const TIMEOUT: Duration = Duration::from_secs(3u64);

// TODO: maybe split this file into smaller mods

#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
	#[error("Request error: {0}")]
	RquestError(String),

	#[error("Other error: {0}")]
	OtherError(String),
}

pub trait HttpVerifier<K>
where
	// the TEE shielding key used to decrypt the http response
	K: ShieldingCryptoEncrypt + ShieldingCryptoDecrypt + Clone,
{
	// merged into one fn, as normally you won't expect to have
	// one trait fn to call another internally
	//
	// this is a synchronous call
	fn make_http_request_and_verify(&self, key: K) -> Result<(), Error>;
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct Web2IdentityVerification<T> {
	pub verification_request: Web2IdentityVerificationRequest,
	pub _marker: PhantomData<T>,
}

pub trait DecryptionVerificationPayload<K: ShieldingCryptoDecrypt> {
	fn decrypt_ciphertext(&self, key: K) -> Result<Vec<u8>, Error>;
}

pub trait UserInfo {
	fn get_user_id(&self) -> Option<String>;
}

struct Web2HttpsClient {
	client: RestClient<HttpClient<DefaultSend>>,
	path: String,
	query: Vec<(String, String)>,
}

impl<R> Web2IdentityVerification<R> {
	fn make_client(&self) -> Result<Web2HttpsClient, Error> {
		let request = &self.verification_request;
		match request.validation_data {
			Web2ValidationData::Twitter(TwitterValidationData { ref tweet_id }) => {
				let token = std::env::var("TWITTER_AUTHORIZATION_TOKEN")
					.map_err(|_| Error::OtherError("token error".to_string()))?;
				let tweet_id = String::from_utf8(tweet_id.to_vec())
					.map_err(|_| Error::OtherError("tweet_id utf8 error".to_string()))?;

				let tweet_id = tweet_id.trim();
				if tweet_id.is_empty() {
					return Err(Error::OtherError("tweet_id is empty".to_string()))
				}

				let client = build_client_with_authorization(TWITTER_BASE_URL, token.as_str());

				Ok(Web2HttpsClient {
					client,
					path: "/2/tweets".to_string(),
					query: vec![
						("ids".to_string(), tweet_id.to_string()),
						("expansions".to_string(), "author_id".to_string()),
					],
				})
			},
			Web2ValidationData::Discord(ref validation_data) => {
				let token = std::env::var("DISCORD_AUTHORIZATION_TOKEN")
					.map_err(|_| Error::OtherError("token error".to_string()))?;
				let channel_id = String::from_utf8(validation_data.channel_id.to_vec())
					.map_err(|_| Error::OtherError("channel_id utf8 error".to_string()))?;
				let message_id = String::from_utf8(validation_data.message_id.to_vec())
					.map_err(|_| Error::OtherError("message_id utf8 error".to_string()))?;

				let channel_id = channel_id.trim();
				let message_id = message_id.trim();
				if channel_id.is_empty() {
					return Err(Error::OtherError("channel_id is empty".to_string()))
				}
				if message_id.is_empty() {
					return Err(Error::OtherError("message_id is empty".to_string()))
				}

				let client = build_client_with_authorization(DISCORD_BASE_URL, token.as_str());
				Ok(Web2HttpsClient {
					client,
					path: format!("/api/channels/{}/messages/{}", channel_id, message_id),
					query: vec![],
				})
			},
		}
	}
}

impl<K, R> HttpVerifier<K> for Web2IdentityVerification<R>
where
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	R: UserInfo + DecryptionVerificationPayload<K> + Debug + DeserializeOwned + RestPath<String>,
{
	fn make_http_request_and_verify(&self, key: K) -> Result<(), Error> {
		let mut client = self.make_client()?;
		let query: Vec<(&str, &str)> =
			client.query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
		let response: R = client
			.client
			.get_with::<String, R>(client.path, query.as_slice())
			.map_err(|e| Error::RquestError(format!("{:?}", e)))?;

		log::debug!("http response:{:?}", response);

		let request = &self.verification_request;
		let payload = response
			.decrypt_ciphertext(key.clone())
			.map_err(|_| Error::OtherError("decrypt payload error".to_string()))?;

		let user_id = response
			.get_user_id()
			.ok_or_else(|| Error::OtherError("can not find user_id".to_string()))?;

		// the user_id must match, is it case sensitive?
		match request.identity.handle {
			IdentityHandle::String(ref handle) => {
				let handle = std::str::from_utf8(handle.as_slice())
					.map_err(|_| Error::OtherError("convert IdentityHandle error".to_string()))?;
				if !user_id.eq(handle) {
					return Err(Error::OtherError("user_id not match".to_string()))
				}
			},
			_ => return Err(Error::OtherError("IdentityHandle not support".to_string())),
		}

		// the payload must match
		// TODO: maybe move it to common place
		ensure!(
			payload
				== get_expected_payload(
					&self.verification_request.who,
					&self.verification_request.identity,
					&self.verification_request.challenge_code
				),
			Error::OtherError("payload not match".to_string())
		);

		Ok(())
	}
}

pub fn build_client(base_url: Url, headers: Headers) -> RestClient<HttpClient<DefaultSend>> {
	let http_client = HttpClient::new(DefaultSend {}, true, Some(TIMEOUT), Some(headers), None);
	RestClient::new(http_client, base_url)
}

pub fn build_client_with_authorization(
	base_url: &str,
	authorization_token: &str,
) -> RestClient<HttpClient<DefaultSend>> {
	let base_url = Url::parse(base_url).unwrap();
	let mut headers = Headers::new();
	headers.insert(CONNECTION.as_str(), "close");
	headers.insert(AUTHORIZATION.as_str(), authorization_token);
	build_client(base_url, headers)
}
