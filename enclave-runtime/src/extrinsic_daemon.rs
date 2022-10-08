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
	global_components::{
		GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT,
		GLOBAL_PARENTCHAIN_BLOCK_VALIDATOR_ACCESS_COMPONENT,
		GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT,
	},
	GLOBAL_STATE_HANDLER_COMPONENT,
};
use itc_extrinsic_request_daemon::{
	xt_daemon_sender, Assertion1Request, Assertion2Request, AssertionType, RequestType,
	SetChallengeCodeRequest, Web2IdentityVerificationRequest,
};
use log::*;
use sgx_types::sgx_status_t;
use std::{string::ToString, sync::Arc};

use ita_sgx_runtime::Runtime;
use itc_parentchain::light_client::{concurrent_access::ValidatorAccess, LightClientState};

use crate::global_components::{
	EnclaveStfEnclaveSigner, GLOBAL_OCALL_API_COMPONENT, GLOBAL_STATE_OBSERVER_COMPONENT,
	GLOBAL_TOP_POOL_AUTHOR_COMPONENT,
};

use ita_stf::{Hash, State as StfState};
use itc_account_request_handler::{
	web2_identity::{discord, twitter},
	RequestContext, RequestHandler,
};
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::{CreateExtrinsics, ExtrinsicsFactory};
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_sgx_crypto::{Ed25519Seal, Rsa3072Seal, ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_sgx_io::StaticSealedIO;
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{OpaqueCall, ShardIdentifier};
use litentry_primitives::Web2ValidationData;

#[no_mangle]
pub unsafe extern "C" fn run_extrinsic_request_daemon() -> sgx_status_t {
	if let Err(e) = run_extrinsic_request_daemon_internal() {
		error!("Error while running extrinsic request daemon: {:?}", e);
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`run_extrinsic_request_daemon`] function to be able to use the `?` operator.
///
/// Runs an extrinsic request inside the enclave, opening a channel and waiting for
/// senders to send requests.
fn run_extrinsic_request_daemon_internal() -> Result<()> {
	let receiver = xt_daemon_sender::init_xt_daemon_sender_storage()?;

	let validator_access = GLOBAL_PARENTCHAIN_BLOCK_VALIDATOR_ACCESS_COMPONENT.get()?;

	// This gets the latest imported block. We accept that all of AURA, up until the block production
	// itself, will  operate on a parentchain block that is potentially outdated by one block
	// (in case we have a block in the queue, but not imported yet).
	let (_, genesis_hash) = validator_access.execute_on_validator(|v| {
		let latest_parentchain_header = v.latest_finalized_header(v.num_relays())?;
		let genesis_hash = v.genesis_hash(v.num_relays())?;
		Ok((latest_parentchain_header, genesis_hash))
	})?;
	let authority = Ed25519Seal::unseal_from_static_file()?;
	let node_metadata_repository = GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT.get()?;

	let extrinsics_factory = ExtrinsicsFactory::new(
		genesis_hash,
		authority,
		GLOBAL_NONCE_CACHE.clone(),
		node_metadata_repository,
	);

	let author_api = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;
	let state_observer = GLOBAL_STATE_OBSERVER_COMPONENT.get()?;
	// For debug purposes, list shards. no problem to panic if fails.
	let shards = state_handler.list_shards().unwrap();
	let default_shard_identifier: ShardIdentifier = if let Some(shard) = shards.get(0) {
		Ok(sp_core::H256::from_slice(shard.as_bytes()))
	} else {
		Err(Error::Stf("Could not retrieve shard".to_string()))
	}?;

	let stf_state: StfState =
		state_handler.load(&default_shard_identifier).map_err(Error::StfStateHandler)?;
	let stf_state = Arc::new(stf_state);

	let shielding_key_repository = GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get()?;
	let shielding_key = Rsa3072Seal::unseal_from_static_file().unwrap();

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let stf_enclave_signer =
		Arc::new(EnclaveStfEnclaveSigner::new(state_observer, ocall_api, shielding_key_repository));

	let request_context = RequestContext::new(
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

fn web2_identity_verification<
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
>(
	request_context: &RequestContext<K, A, S>,
	request: Web2IdentityVerificationRequest,
) -> core::result::Result<(), itc_account_request_handler::Error> {
	match &request.validation_data {
		Web2ValidationData::Twitter(_) => {
			let handler = itc_account_request_handler::web2_identity::Web2IdentityVerification::<
				twitter::TwitterResponse,
			> {
				verification_request: request,
				_marker: Default::default(),
			};
			handler.send_request(request_context)
		},
		Web2ValidationData::Discord(_) => {
			let handler = itc_account_request_handler::web2_identity::Web2IdentityVerification::<
				discord::DiscordResponse,
			> {
				verification_request: request,
				_marker: Default::default(),
			};
			handler.send_request(request_context)
		},
	}
}

fn feedback_via_ocall<F: CreateExtrinsics>(
	module_id: u8,
	method_id: u8,
	extrinsics_factory: &F,
) -> Result<()> {
	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let call = OpaqueCall::from_tuple(&([module_id, method_id],));
	let calls = std::vec![call];
	let tx = extrinsics_factory.create_extrinsics(calls.as_slice(), None)?;

	let result = ocall_api.send_to_parentchain(tx)?;
	debug!("extrinsic daemon send tx result as ( {:?},)", result);

	Ok(())
}

fn verify_assertion1<F: CreateExtrinsics>(request: &Assertion1Request, extrinsics_factory: &F) {
	let v_did_context =
	ita_sgx_runtime::pallet_identity_management::Pallet::<Runtime>::get_identity_and_identity_context(&request.target);

	let mut web2_cnt = 0;
	let mut web3_cnt = 0;

	for did_ctx in &v_did_context {
		if did_ctx.1.is_verified {
			if did_ctx.0.is_web2() {
				web2_cnt += 1;
			} else if did_ctx.0.is_web3() {
				web3_cnt += 1;
			}
		}
	}

	if web2_cnt > 0 && web3_cnt > 0 {
		// TODO: align with Parachain pallet module_id and method_id
		let module_id = 64u8;
		let method_id = 0u8;
		let _err = feedback_via_ocall(module_id, method_id, extrinsics_factory);
	}
}

fn verify_assertion2<F: CreateExtrinsics>(_request: &Assertion2Request, _extrinsics_factory: &F) {
	// TODO
}

fn set_challenge_code(_request: &SetChallengeCodeRequest) {
	// TODO
}