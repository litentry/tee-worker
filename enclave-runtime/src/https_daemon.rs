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
use itc_https_client_daemon::{daemon_sender, RequestType, Web2IdentityVerificationRequest};
use log::*;
use sgx_types::sgx_status_t;
use std::{string::ToString, sync::Arc};

use itc_parentchain::light_client::{concurrent_access::ValidatorAccess, LightClientState};

use crate::global_components::{
	EnclaveStfEnclaveSigner, GLOBAL_OCALL_API_COMPONENT, GLOBAL_STATE_OBSERVER_COMPONENT,
	GLOBAL_TOP_POOL_AUTHOR_COMPONENT,
};

use ita_stf::{Hash, State as StfState};
use itc_https_request_handler::{
	web2_identity::{discord, twitter},
	RequestContext, RequestHandler,
};
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_sgx_crypto::{Ed25519Seal, Rsa3072Seal, ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_sgx_externalities::{SgxExternalities, SgxExternalitiesTrait};
use itp_sgx_io::StaticSealedIO;
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_top_pool_author::traits::AuthorApi;
use itp_types::ShardIdentifier;
use litentry_primitives::Web2ValidationData;

const HTTPS_ADDRESS: &str = "https://api.coingecko.com";

#[no_mangle]
pub unsafe extern "C" fn run_https_client_daemon() -> sgx_status_t {
	if let Err(e) = run_https_client_daemon_internal(HTTPS_ADDRESS) {
		error!("Error while running https client daemon: {:?}", e);
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`run_https_client_daemon`] function to be able to use the `?` operator.
///
/// Runs an https client inside the enclave, opening a channel and waiting for
/// senders to send requests.
fn run_https_client_daemon_internal(_url: &str) -> Result<()> {
	let receiver = daemon_sender::init_https_daemon_sender_storage()?;

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

	let _extrinsics_factory = ExtrinsicsFactory::new(
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

	let stf_state: StfState = state_handler
		.load(&default_shard_identifier)
		.map_err(|e| Error::StfStateHandler(e))?;
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
			RequestType::RuleSet => {
				//TODO
				error!("ruleset don't support yet");
			},
			RequestType::Web3IndentityVerification => {
				error!("web3 don't support yet");
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
) -> core::result::Result<(), itc_https_request_handler::Error> {
	match &request.validation_data {
		Web2ValidationData::Twitter(_) => {
			let handler = itc_https_request_handler::web2_identity::Web2IdentityVerification::<
				twitter::TwitterResponse,
			> {
				verification_request: request,
				_marker: Default::default(),
			};
			handler.send_request(request_context)
		},
		Web2ValidationData::Discord(_) => {
			let handler = itc_https_request_handler::web2_identity::Web2IdentityVerification::<
				discord::DiscordResponse,
			> {
				verification_request: request,
				_marker: Default::default(),
			};
			handler.send_request(request_context)
		},
	}
}
