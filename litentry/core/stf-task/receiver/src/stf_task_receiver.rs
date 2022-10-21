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

use crate::{
	format, AuthorApi, Error, Hash, ShieldingCryptoDecrypt, ShieldingCryptoEncrypt,
	StfEnclaveSigning, StfExecuteGenericUpdate, StfTaskContext,
};
use frame_support::traits::UnfilteredDispatchable;
use ita_sgx_runtime::Runtime;
use lc_identity_verification::web2::{discord, twitter, HttpVerifier, Web2IdentityVerification};
use lc_stf_task_sender::{stf_task_sender, RequestType};
use litentry_primitives::Web2ValidationData;
use log::*;

// lifetime elision: StfTaskContext is guaranteed to outlive the fn
pub fn run_stf_task_receiver<K, A, S, E>(context: &StfTaskContext<K, A, S, E>) -> Result<(), Error>
where
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
	E: StfExecuteGenericUpdate,
{
	let receiver = stf_task_sender::init_stf_task_sender_storage()
		.map_err(|e| Error::OtherError(format!("read storage error:{:?}", e)))?;

	// TODO: better error handling for this loop
	//       we shouldn't panic when processing tasks
	loop {
		let request_type = receiver
			.recv()
			.map_err(|e| Error::OtherError(format!("receiver error:{:?}", e)))?;

		match request_type {
			// TODO: further simplify this
			RequestType::Web2IdentityVerification(request) => {
				match request.validation_data {
					Web2ValidationData::Twitter(_) => {
						let verifier = Web2IdentityVerification::<twitter::TwitterResponse> {
							verification_request: request.clone(),
							_marker: Default::default(),
						};

						let _ = verifier
							.make_http_request_and_verify(context.shielding_key.clone())
							.map_err(|e| {
								Error::OtherError(format!("error send request {:?}", e))
							})?;
					},
					Web2ValidationData::Discord(_) => {
						let verifier = Web2IdentityVerification::<discord::DiscordResponse> {
							verification_request: request.clone(),
							_marker: Default::default(),
						};

						let _ = verifier
							.make_http_request_and_verify(context.shielding_key.clone())
							.map_err(|e| {
								Error::OtherError(format!("error send request {:?}", e))
							})?;
					},
				};

				let c = context.create_verify_identity_trusted_call(
					request.who,
					request.identity,
					request.bn,
				)?;
				let _ = context.submit_trusted_call(&c)?;
			},
			RequestType::Web3IdentityVerification(request) => {
				let _ = lc_identity_verification::web3::verify(
					request.who.clone(),
					request.identity.clone(),
					request.challenge_code,
					request.validation_data.clone(),
				)
				.map_err(|e| Error::OtherError(format!("error verify web3: {:?}", e)))?;

				let c = context.create_verify_identity_trusted_call(
					request.who,
					request.identity,
					request.bn,
				)?;
				let _ = context.submit_trusted_call(&c)?;
			},
			RequestType::RulesetVerification(request) =>
				for identity in request.vec_identity {
					let result = lc_ruleset_build::build_ruleset(
						request.who.clone(),
						identity,
						request.ruleset.clone(),
					)
					.map_err(|e| Error::RulesetError(format!("error verify ruleset: {:?}", e)));

					if result.is_ok() {
						// When result is Ok,
						break
					}
				},

			RequestType::SetUserShieldingKey(request) => {
				// demonstrate how to read storage, an alternative is to use `ext.get()` in the upper level
				let key = context.read_or_update_state(|| {
					let k = ita_sgx_runtime::IdentityManagement::user_shielding_keys(
						request.who.clone(),
					);

					Ok(k)
				})?;

				warn!("demo current shielding key is {:?}", key);

				// demonstrate how to write storage
				let _ = context.read_or_update_state(|| {
					let _ = ita_sgx_runtime::IdentityManagementCall::<Runtime>::set_user_shielding_key {
						who: request.who.clone(),
						key: request.key,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
					.map_err(|e| Error::RulesetError(format!("error user_shielding_key: {:?}", e)))?;
					Ok(())
				})?;
			},
			_ => {
				unimplemented!()
			},
		}
	}
}
