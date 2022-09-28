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
	format, str, vec, DecryptionVerificationPayload, Error, RequestContext, RequestHandler, String,
	ToString, UserInfo, Vec,
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use futures::executor;
use ita_stf::{Hash, TrustedCall, TrustedOperation};
use itc_https_client_daemon::Web2IdentityVerificationRequest;
use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath,
};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_top_pool_author::traits::AuthorApi;
use litentry_primitives::{
	IdentityHandle, TwitterValidationData, ValidationData, Web2ValidationData,
};
use serde::de::DeserializeOwned;
use sp_core::ByteArray;
use std::marker::PhantomData;

pub mod discord;
pub mod twitter;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct Web2IdentityVerification<T> {
	pub verification_request: Web2IdentityVerificationRequest,
	pub _marker: PhantomData<T>,
}

impl<
		A: AuthorApi<Hash, Hash>,
		S: StfEnclaveSigning,
		K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
		R: UserInfo + DecryptionVerificationPayload<K> + Debug + DeserializeOwned + RestPath<String>,
	> RequestHandler<K, A, S> for Web2IdentityVerification<R>
{
	type Response = R;

	fn send_request(
		&self,
		verification_context: &RequestContext<K, A, S>,
		mut client: RestClient<HttpClient<DefaultSend>>,
		path: String,
	) -> Result<(), Error> {
		let request = &self.verification_request;
		let query: Vec<(&str, &str)> = match request.validation_data {
			Web2ValidationData::Twitter(TwitterValidationData { ref tweet_id }) => {
				vec![
					("ids", str::from_utf8(tweet_id.as_slice()).unwrap()),
					("expansions", "author_id"),
				]
			},
			Web2ValidationData::Discord(_) => {
				vec![]
			},
		};
		let response: Self::Response = client
			.get_with::<String, R>(path, query.as_slice())
			.map_err(|e| Error::RquestError(format!("{:?}", e)))?;
		log::warn!("response:{:?}", response);
		self.handle_response(verification_context, response)
	}

	fn handle_response(
		&self,
		verification_context: &RequestContext<K, A, S>,
		response: Self::Response,
	) -> Result<(), Error> {
		let request = &self.verification_request;
		let payload = response
			.decrypt_ciphertext(verification_context.shielding_key.clone())
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

		let enclave_account_id = verification_context
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
				.submit_top(encrypted_trusted_call, verification_context.shard_identifier)
				.await
		};
		executor::block_on(top_submit_future).map_err(|e| {
			Error::OtherError(format!("Error adding indirect trusted call to TOP pool: {:?}", e))
		})?;

		Ok(())
	}
}
