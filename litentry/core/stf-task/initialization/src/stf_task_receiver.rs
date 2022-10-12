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
	error::{Error, Result},
	stf_task_sender, AssertionType, RequestType,
};
use log::error;

fn run_stf_task_receiver() -> Result<()> {
	let receiver = stf_task_sender::init_stf_task_sender_storage()?;

	let request_context = VerifyContext::new(
		default_shard_identifier,
		stf_state,
		shielding_key,
		stf_enclave_signer,
		author_api,
	);
	loop {
		let request_type = receiver.recv().map_err(|e| Error::Other(e.into()))?;

		match request_type {
			RequestType::Web2IdentityVerification(ref request) => {
				if let Err(e) = web2_identity_verification(&request_context, request.clone()) {
					error!("Could not retrieve data from https server due to: {:?}", e);
				}
			},
			RequestType::Web3IndentityVerification(ref _request) => {
				error!("web3 don't support yet");
			},
			RequestType::Assertion(AssertionType::AssertionType1(ref request)) => {
				verify_assertion1(request, &extrinsics_factory);
			},
			RequestType::Assertion(AssertionType::AssertionType2(ref request)) => {
				verify_assertion2(request, &extrinsics_factory);
			},
			RequestType::SetChallengeCode(ref request) => {
				set_challenge_code(request);
			},
		}
	}
}
