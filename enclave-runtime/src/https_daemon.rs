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
	global_components::GLOBAL_PARENTCHAIN_BLOCK_VALIDATOR_ACCESS_COMPONENT,
	ocall::OcallApi,
};
use itc_https_client_daemon::{daemon_sender, https_client::HttpsRestClient};
use log::*;
use sgx_types::sgx_status_t;
use url::Url;

use itc_parentchain::light_client::{concurrent_access::ValidatorAccess, LightClientState};

use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_sgx_crypto::Ed25519Seal;
use itp_sgx_io::StaticSealedIO;
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

	let extrinsics_factory =
		ExtrinsicsFactory::new(genesis_hash, authority, GLOBAL_NONCE_CACHE.clone());

	let mut daemon = HttpsRestClient::new(Url::parse(url)?, OcallApi {}, extrinsics_factory);

	loop {
		let request = receiver.recv().map_err(|e| Error::Other(e.into()))?;
		if let Err(e) = daemon.send(request) {
			error!("Could not retrieve data from https server due to: {:?}", e);
		}
	}
}
