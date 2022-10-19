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
	StfEnclaveSigning, StfTaskContext,
};
use lc_identity_verification::web2::{discord, twitter, HttpVerifier, Web2IdentityVerification};
use lc_stf_task_sender::{stf_task_sender, RequestType};
use litentry_primitives::{Assertion, IdentityWebType, Web2Network, Web2ValidationData};

// lifetime elision: StfTaskContext is guaranteed to outlive the fn
pub fn run_stf_task_receiver<K, A, S>(context: &StfTaskContext<K, A, S>) -> Result<(), Error>
where
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
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
			RequestType::AssertionVerification(request) => {
				match request.assertion {
					Assertion::Assert1 => {},
					Assertion::Assert2(guilt_id, user_id) => {
						for identity in request.vec_identity {
							if identity.web_type == IdentityWebType::Web2(Web2Network::Discord) {
								let result = lc_assertion_build::build_assertion2(
									guilt_id.clone(),
									user_id.clone(),
								)
								.map_err(|e| {
									Error::AssertionError(format!(
										"error verify assertion: {:?}",
										e
									))
								});

								if result.is_ok() {
									// When result is Ok,
									break
								}
							}
						}
					},
					_ => {
						unimplemented!()
					},
				}
			},
			_ => {
				unimplemented!()
			},
		}
	}
}
