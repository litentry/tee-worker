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
use crate::{
	build_client_with_authorization, format, str, vec, DecryptionVerificationPayload, Error,
	RequestContext, RequestHandler, String, ToString, UserInfo, Vec,
};
use codec::{Decode, Encode};
// use core::{borrow::BorrowMut, fmt::Debug, ops::Deref};
use core::fmt::Debug;
use futures::executor;
use ita_stf::{Hash, ShardIdentifier, TrustedCall, TrustedOperation};
use itc_extrinsic_request_daemon::Web2IdentityVerificationRequest;
use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath,
};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_storage::{storage_double_map_key, StorageHasher};
use itp_top_pool_author::traits::AuthorApi;
use litentry_primitives::{
	IdentityHandle, TwitterValidationData, ValidationData, Web2ValidationData,
};
use serde::de::DeserializeOwned;
use sp_core::ByteArray;
use std::marker::PhantomData;

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

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct Web2IdentityVerification<T> {
	pub verification_request: Web2IdentityVerificationRequest,
	pub _marker: PhantomData<T>,
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

impl<
		A: AuthorApi<Hash, Hash>,
		S: StfEnclaveSigning,
		K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
		R: UserInfo + DecryptionVerificationPayload<K> + Debug + DeserializeOwned + RestPath<String>,
	> RequestHandler<K, A, S> for Web2IdentityVerification<R>
{
	type Response = R;

	fn send_request(&self, request_context: &RequestContext<K, A, S>) -> Result<(), Error> {
		let mut client = self.make_client()?;
		let query: Vec<(&str, &str)> =
			client.query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
		let response: Self::Response = client
			.client
			.get_with::<String, R>(client.path, query.as_slice())
			.map_err(|e| Error::RquestError(format!("{:?}", e)))?;
		//TODO log level
		log::warn!("response:{:?}", response);
		self.handle_response(request_context, response)
	}

	fn handle_response(
		&self,
		request_context: &RequestContext<K, A, S>,
		response: Self::Response,
	) -> Result<(), Error> {
		{
			// for testing...
			let key = storage_double_map_key(
				"IdentityManagement",
				"ChallengeCodes",
				&self.verification_request.target,
				&StorageHasher::Blake2_128Concat,
				&self.verification_request.identity,
				&StorageHasher::Blake2_128Concat,
			);
			let mut state = itp_sgx_externalities::SgxExternalities::new();

			state.execute_with(|| {
				log::warn!("storage--key: {:?}", key);
				let code: Option<u32> = ita_stf::helpers::get_storage_by_key_hash(key);
				log::warn!("code: {:?}", code);
			});
		}

		let request = &self.verification_request;
		let payload = response
			.decrypt_ciphertext(request_context.shielding_key.clone())
			.map_err(|_| Error::OtherError("decrypt payload error".to_string()))?;

		let user_id = response
			.get_user_id()
			.ok_or_else(|| Error::OtherError("can not find user_id".to_string()))?;

		match payload.identity.handle {
			IdentityHandle::String(ref handle) => {
				let handle = std::str::from_utf8(handle.as_slice())
					.map_err(|_| Error::OtherError("convert IdentityHandle error".to_string()))?;
				if !user_id.eq(handle) {
					return Err(Error::OtherError("user_id is not the same".to_string()))
				}
			},
			_ => return Err(Error::OtherError("IdentityHandle not support".to_string())),
		}

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

		let enclave_account_id = request_context
			.enclave_signer
			.get_enclave_account()
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

		let trusted_call = TrustedCall::verify_identity_step2(
			enclave_account_id,
			request.target.clone(),
			request.identity.clone(),
			ValidationData::Web2(request.validation_data.clone()),
			request.bn,
		);
		submit_call(
			request_context.enclave_signer.as_ref(),
			&request_context.shielding_key,
			request_context.author.as_ref(),
			request_context.shard_identifier,
			&trusted_call,
		)
	}
}

fn submit_call<
	K: ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
>(
	enclave_signer: &S,
	shielding_key: &K,
	author_api: &A,
	shard_identifier: ShardIdentifier,
	trusted_call: &TrustedCall,
) -> Result<(), Error> {
	let signed_trusted_call = enclave_signer
		.sign_call_with_self(trusted_call, &shard_identifier)
		.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

	let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);

	let encrypted_trusted_call = shielding_key
		.encrypt(&trusted_operation.encode())
		.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

	let top_submit_future =
		async { author_api.submit_top(encrypted_trusted_call, shard_identifier).await };
	executor::block_on(top_submit_future).map_err(|e| {
		Error::OtherError(format!("Error adding indirect trusted call to TOP pool: {:?}", e))
	})?;

	Ok(())
}
