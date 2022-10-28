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
	format, AuthorApi, Error, HandleState, Hash, ShardIdentifier, ShieldingCryptoDecrypt,
	ShieldingCryptoEncrypt, StfEnclaveSigning, StfTaskContext, TrustedCall,
};
use codec::Decode;
use frame_support::traits::UnfilteredDispatchable;
use ita_sgx_runtime::Runtime;
use lc_stf_task_sender::{stf_task_sender, RequestType};
use litentry_primitives::{Assertion, IdentityWebType, Web2Network, Web2ValidationData};
use log;

// lifetime elision: StfTaskContext is guaranteed to outlive the fn
pub fn run_stf_task_receiver<K, A, S, H>(context: &StfTaskContext<K, A, S, H>) -> Result<(), Error>
where
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
	H: HandleState,
{
	let receiver = stf_task_sender::init_stf_task_sender_storage()
		.map_err(|e| Error::OtherError(format!("read storage error:{:?}", e)))?;

	// TODO: When an error occurs, send the extrinsic (error message) to the parachain
	// TODO: error handling still incomplete, we only print logs but no error handling
	loop {
		let request_type = receiver
			.recv()
			.map_err(|e| Error::OtherError(format!("receiver error:{:?}", e)))?;

		match request_type {
			// TODO: further simplify this
			RequestType::Web2IdentityVerification(request) =>
				match lc_identity_verification::web2::verify(request.clone()) {
					Err(e) => {
						log::error!("error verify web2: {:?}", e)
					},
					Ok(_) => {
						let callback = TrustedCall::decode(
							&mut request.encoded_callback.as_slice(),
						)
						.map_err(|e| {
							Error::OtherError(format!("error decoding TrustedCall {:?}", e))
						})?;
						let shard = ShardIdentifier::decode(&mut request.encoded_shard.as_slice())
							.map_err(|e| {
								Error::OtherError(format!("error decoding ShardIdentifier {:?}", e))
							})?;
						let _ = context.submit_trusted_call(&shard, &callback)?;
					},
				},
			RequestType::Web3IdentityVerification(request) =>
				match lc_identity_verification::web3::verify(
					request.who.clone(),
					request.identity.clone(),
					request.challenge_code,
					request.validation_data.clone(),
				) {
					Err(e) => {
						log::error!("error verify web3: {:?}", e)
					},
					Ok(_) => {
						let callback = TrustedCall::decode(
							&mut request.encoded_callback.as_slice(),
						)
						.map_err(|e| {
							Error::OtherError(format!("error decoding TrustedCall {:?}", e))
						})?;
						let shard = ShardIdentifier::decode(&mut request.encoded_shard.as_slice())
							.map_err(|e| {
								Error::OtherError(format!("error decoding ShardIdentifier {:?}", e))
							})?;
						let _ = context.submit_trusted_call(&shard, &callback)?;
					},
				},
			RequestType::AssertionVerification(request) => match request.assertion {
				Assertion::A1 => {
					if let Err(e) = lc_assertion_build::a1::build(request.vec_identity) {
						log::error!("error verify assertion1: {:?}", e)
					}
				},
				Assertion::A2(guild_id, handler) => {
					for identity in request.vec_identity {
						if identity.web_type == IdentityWebType::Web2(Web2Network::Discord) {
							if let Err(e) =
								lc_assertion_build::a2::build(guild_id.clone(), handler.clone())
							{
								log::error!("error verify assertion2: {:?}", e)
							} else {
								// When result is Ok,
								break
							}
						}
					}
				},
				Assertion::A3(guild_id, handler) => {
					for identity in request.vec_identity {
						if identity.web_type == IdentityWebType::Web2(Web2Network::Discord) {
							if let Err(e) =
								lc_assertion_build::a3::build(guild_id.clone(), handler.clone())
							{
								log::error!("error verify assertion3: {:?}", e)
							} else {
								// When result is Ok,
								break
							}
						}
					}
				},
				_ => {
					unimplemented!()
				},
			},

			RequestType::SetUserShieldingKey(request) => {
				// demonstrate how to read storage, an alternative is to use `ext.get()` in the upper level
			},
			_ => {
				unimplemented!()
			},
		}
	}
}
