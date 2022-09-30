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
		GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT, GLOBAL_OCALL_API_COMPONENT,
		GLOBAL_PARENTCHAIN_BLOCK_VALIDATOR_ACCESS_COMPONENT,
	},
};
use ita_sgx_runtime::Runtime;
use itc_parentchain::light_client::{concurrent_access::ValidatorAccess, LightClientState};
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::{CreateExtrinsics, ExtrinsicsFactory};
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_sgx_crypto::Ed25519Seal;
use itp_sgx_io::StaticSealedIO;
use itp_types::OpaqueCall;
// use litentry_primitives::Identity;
use log::*;
use sgx_types::sgx_status_t;

use itc_assertions_verify_daemon::{
	verify_daemon_sender::init_verify_daemon_sender_storage, AssertionIndex, AssertionVerifyRequest,
};

#[no_mangle]
pub unsafe extern "C" fn run_assertions_verify_daemon() -> sgx_status_t {
	if let Err(e) = run_assertions_verify_daemon_internal() {
		error!("Error while running https client daemon: {:?}", e);
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

fn run_assertions_verify_daemon_internal() -> Result<()> {
	let receiver = init_verify_daemon_sender_storage()?;

	let validator_access = GLOBAL_PARENTCHAIN_BLOCK_VALIDATOR_ACCESS_COMPONENT.get()?;

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

	loop {
		let request = receiver.recv().map_err(|e| Error::Other(e.into()))?;

		match request.assertion_idx {
			AssertionIndex::Assertion1 => verify_assertion1(&request, &extrinsics_factory),
			_ => println!("Undefined Assertion"),
		}
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
	let tx = extrinsics_factory
		.create_extrinsics(calls.as_slice(), None)
		.map_err(|e| Error::ExtrinsicsFactory(e))?;

	let result = ocall_api.send_to_parentchain(tx).map_err(|e| Error::Sgx(e))?;
	debug!("https daemon send tx result as ( {:?},)", result);

	Ok(())
}

fn verify_assertion1<F: CreateExtrinsics>(
	request: &AssertionVerifyRequest,
	extrinsics_factory: &F,
) {
	let v_did_context =
	ita_sgx_runtime::pallet_identity_management::Pallet::<Runtime>::get_identity_and_identity_context(&request.who);

	let mut web2_cnt = 0;
	let mut web3_cnt = 0;

	for did_ctx in &v_did_context {
		if did_ctx.1.is_verified {
			if did_ctx.0.is_web2() {
				web2_cnt = web2_cnt + 1;
			} else if did_ctx.0.is_web3() {
				web3_cnt = web3_cnt + 1;
			}
		}
	}

	if web2_cnt > 0 && web3_cnt > 0 {
		// TODO: align with Parachain pallet module_id and method_id
		let module_id = 64u8;
		let method_id = 0u8;
		feedback_via_ocall(module_id, method_id, extrinsics_factory);
	}
}

// fn verify_assertion2<F: CreateExtrinsics>(request: &AssertionVerifyRequest, extrinsics_factory: &F) {}

// fn verify_assertion3<F: CreateExtrinsics>(request: &AssertionVerifyRequest, extrinsics_factory: &F) {}
