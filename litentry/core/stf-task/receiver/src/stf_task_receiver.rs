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
use lc_stf_task_sender::{stf_task_sender, RequestType};
use litentry_primitives::{Assertion, IdentityWebType, Web2Network};
use log::log;

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
				if let Err(e) = lc_identity_verification::web2::verify(request.clone()) {
					log::error!("error verify web2: {:?}", e)
				}

				match context.create_verify_identity_trusted_call(
					request.who,
					request.identity,
					request.bn,
				) {
					Ok(c) =>
						if let Err(e) = context.submit_trusted_call(&c) {
							log::error!("submit call(verify_identity) error: {:?}", e)
						},
					Err(e) => {
						log::error!("create call error: {:?}", e)
					},
				}
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
					Assertion::A1 => {
						lc_assertion_build::a1::build(request.vec_identity).map_err(|e| {
							Error::AssertionError(format!("error verify assertion: {:?}", e))
						})?;
					},
					Assertion::A2(guild_id, user_id) => {
						for identity in request.vec_identity {
							if identity.web_type == IdentityWebType::Web2(Web2Network::Discord) {
								let result = lc_assertion_build::a2::build(
									guild_id.clone(),
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
