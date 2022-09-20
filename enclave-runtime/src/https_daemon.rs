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
use itc_https_client_daemon::daemon_sender;
use log::*;
use sgx_types::sgx_status_t;
use std::{
	string::{String, ToString},
	sync::Arc,
};

use itc_parentchain::light_client::{concurrent_access::ValidatorAccess, LightClientState};

use crate::global_components::{
	EnclaveStfEnclaveSigner, GLOBAL_OCALL_API_COMPONENT, GLOBAL_TOP_POOL_AUTHOR_COMPONENT,
};
use itc_https_request_handler::{
	build_twitter_client, CommonHandler, RequestHandler, TwitterResponse, VerificationContext,
};
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_sgx_crypto::{Ed25519Seal, Rsa3072Seal};
use itp_sgx_io::StaticSealedIO;
use itp_stf_state_handler::query_shard_state::QueryShardState;
use litentry_primitives::{TwitterValidationData, Web2ValidationData};

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
fn run_https_client_daemon_internal(url: &str) -> Result<()> {
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
	// For debug purposes, list shards. no problem to panic if fails.
	let shards = state_handler.list_shards().unwrap();
	let default_shard_identifier = shards.get(0).unwrap().clone();

	let shielding_key_repository = GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get()?;
	let shielding_key = Rsa3072Seal::unseal_from_static_file().unwrap();

	let twitter_authorization_token: Option<String> =
		std::env::var("TWITTER_AUTHORIZATION_TOKEN").map_or_else(|_| None, |v| Some(v.to_string()));

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let stf_enclave_signer = Arc::new(EnclaveStfEnclaveSigner::new(
		state_handler.clone(),
		ocall_api,
		shielding_key_repository.clone(),
	));

	// let base_url = Url::parse("https://api.twitter.com")?;
	// let mut daemon = HttpsRestClient::new(
	// 	base_url,
	// 	// Some("Bearer AAAAAAAAAAAAAAAAAAAAALJEfQEAAAAAGv1Jyd%2FkYo3fN4CepxeZMUl8k2g%3D8MnYYQSGpDH8EcvGz7AB2H7hlLP14v1mDKtkqbam1s7itBXC7K".as_bytes().to_vec()),
	// 	authorization_token,
	// 	OcallApi {},
	// 	extrinsics_factory,
	// 	Rsa3072Seal::unseal_from_static_file().unwrap(),
	// 	// author_api,
	// );

	let verification_context = VerificationContext::new(
		default_shard_identifier,
		shielding_key,
		stf_enclave_signer,
		author_api,
	);
	let handler = CommonHandler {};
	loop {
		let request = receiver.recv().map_err(|e| Error::Other(e.into()))?;
		if let Err(e) = match &request.validation_data {
			Web2ValidationData::Twitter(_) => {
				let client = build_twitter_client(twitter_authorization_token.clone());
				handler.send_request::<TwitterResponse>(
					&verification_context,
					client,
					request,
					"/2/tweets".to_string(),
				)
			},
			Web2ValidationData::Discord(_) => {
				// todo!()
				Ok(())
			},
		} {
			error!("Could not retrieve data from https server due to: {:?}", e);
		}
	}
}
