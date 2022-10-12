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

use crate::{Error, StfState};
use ita_stf::{Hash, ShardIdentifier};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_top_pool_author::traits::AuthorApi;
use lc_identity_verification::web2::{
	discord, twitter, VerifyContext, VerifyHandler, Web2IdentityVerification,
};
use lc_stf_task_sender::{stf_task_sender, RequestType, Web2IdentityVerificationRequest};
use litentry_primitives::Web2ValidationData;
use log::error;
use std::{format, sync::Arc};

// TODO: better error handling
pub fn run_stf_task_receiver<
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
>(
	shard_identifier: ShardIdentifier,
	stf_state: Arc<StfState>,
	shielding_key: K,
	stf_enclave_signer: Arc<S>,
	author_api: Arc<A>,
) -> Result<(), Error> {
	let receiver = stf_task_sender::init_stf_task_sender_storage()
		.map_err(|e| Error::OtherError(format!("read storage error:{:?}", e)))?;

	let request_context = VerifyContext::new(
		shard_identifier,
		stf_state,
		shielding_key,
		stf_enclave_signer,
		author_api,
	);
	loop {
		let request_type = receiver
			.recv()
			.map_err(|e| Error::OtherError(format!("receiver error:{:?}", e)))?;

		match request_type {
			RequestType::Web2IdentityVerification(ref request) => {
				if let Err(e) = web2_identity_verification(&request_context, request.clone()) {
					error!("Could not retrieve data from https server due to: {:?}", e);
				}
			},
			RequestType::Web3IdentityVerification(ref _request) => {
				error!("web3 don't support yet");
			},
			_ => {
				error!("Not yet implement");
			},
		}
	}
}

fn web2_identity_verification<
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
>(
	request_context: &VerifyContext<K, A, S>,
	request: Web2IdentityVerificationRequest,
) -> core::result::Result<(), Error> {
	match &request.validation_data {
		Web2ValidationData::Twitter(_) => {
			let handler = Web2IdentityVerification::<twitter::TwitterResponse> {
				verification_request: request,
				_marker: Default::default(),
			};
			handler
				.send_request(request_context)
				.map_err(|e| Error::OtherError(format!("error send request {:?}", e)))
		},
		Web2ValidationData::Discord(_) => {
			let handler = Web2IdentityVerification::<discord::DiscordResponse> {
				verification_request: request,
				_marker: Default::default(),
			};
			handler
				.send_request(request_context)
				.map_err(|e| Error::OtherError(format!("error send request {:?}", e)))
		},
	}
}
