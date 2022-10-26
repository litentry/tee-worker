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

use log::*;
use sgx_types::sgx_status_t;
use std::{string::ToString, sync::Arc};

use itc_parentchain::light_client::{concurrent_access::ValidatorAccess, LightClientState};
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_sgx_crypto::{Ed25519Seal, Rsa3072Seal};
use itp_sgx_io::StaticSealedIO;
use itp_stf_state_handler::query_shard_state::QueryShardState;
use itp_types::ShardIdentifier;
use lc_stf_task_receiver::{stf_task_receiver::run_stf_task_receiver, StfTaskContext};

use crate::{
	error::{Error, Result},
	global_components::{
		EnclaveStfEnclaveSigner, GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT,
		GLOBAL_OCALL_API_COMPONENT, GLOBAL_PARENTCHAIN_BLOCK_VALIDATOR_ACCESS_COMPONENT,
		GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT, GLOBAL_STATE_OBSERVER_COMPONENT,
		GLOBAL_STF_EXECUTOR_COMPONENT, GLOBAL_TOP_POOL_AUTHOR_COMPONENT,
	},
	GLOBAL_STATE_HANDLER_COMPONENT,
};

#[no_mangle]
pub unsafe extern "C" fn run_stf_task_handler() -> sgx_status_t {
	if let Err(e) = run_stf_task_handler_internal() {
		error!("Error while running stf task handler thread: {:?}", e);
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`run_stf_task_handler`] function to be able to use the `?` operator.
///
/// Runs an extrinsic request inside the enclave, opening a channel and waiting for
/// senders to send requests.
fn run_stf_task_handler_internal() -> Result<()> {
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

	let stf_executor = GLOBAL_STF_EXECUTOR_COMPONENT.get()?;

	let shielding_key_repository = GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get()?;
	let shielding_key = Rsa3072Seal::unseal_from_static_file().unwrap();

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let stf_enclave_signer = Arc::new(EnclaveStfEnclaveSigner::new(
		state_observer,
		ocall_api,
		shielding_key_repository,
		author_api.clone(),
	));

	let stf_task_context = StfTaskContext::new(
		default_shard_identifier,
		shielding_key,
		author_api,
		stf_enclave_signer,
		stf_executor,
	);

	run_stf_task_receiver(&stf_task_context).map_err(Error::StfTaskReceiver)
}
