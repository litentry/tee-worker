/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

use crate::{
	error::Result, pallet_imp::IMPCallIndexes, pallet_imp_mock::IMPMockCallIndexes,
	pallet_sidechain::SidechainCallIndexes, pallet_teerex::TeerexCallIndexes,
};
use codec::{Decode, Encode};

#[derive(Default, Encode, Decode, Debug, Clone)]
pub struct NodeMetadataMock {
	teerex_module: u8,
	register_enclave: u8,
	unregister_enclave: u8,
	call_worker: u8,
	processed_parentchain_block: u8,
	shield_funds: u8,
	unshield_funds: u8,
	sidechain_module: u8,
	// litentry
	// IMP
	imp_module: u8,
	imp_set_user_shielding_key: u8,
	imp_link_identity: u8,
	imp_unlink_identity: u8,
	imp_verify_identity: u8,
	imp_user_shielding_key_set: u8,
	imp_challenge_code_generated: u8,
	imp_identity_linked: u8,
	imp_identity_unlinked: u8,
	imp_identity_verified: u8,
	imp_some_error: u8,
	// IMP mock
	imp_mock_module: u8,
	imp_mock_set_user_shielding_key: u8,
	imp_mock_link_identity: u8,
	imp_mock_unlink_identity: u8,
	imp_mock_verify_identity: u8,
	imp_mock_user_shielding_key_set: u8,
	imp_mock_challenge_code_generated: u8,
	imp_mock_identity_linked: u8,
	imp_mock_identity_unlinked: u8,
	imp_mock_identity_verified: u8,
	imp_mock_some_error: u8,

	imported_sidechain_block: u8,
	runtime_spec_version: u32,
	runtime_transaction_version: u32,
}

impl NodeMetadataMock {
	pub fn new() -> Self {
		NodeMetadataMock {
			teerex_module: 50u8,
			register_enclave: 0u8,
			unregister_enclave: 1u8,
			call_worker: 2u8,
			processed_parentchain_block: 3u8,
			shield_funds: 4u8,
			unshield_funds: 5u8,
			sidechain_module: 53u8,
			// litentry
			imp_module: 64u8,
			imp_set_user_shielding_key: 0u8,
			imp_link_identity: 1u8,
			imp_unlink_identity: 2u8,
			imp_verify_identity: 3u8,
			imp_user_shielding_key_set: 4u8,
			imp_challenge_code_generated: 5u8,
			imp_identity_linked: 6u8,
			imp_identity_unlinked: 7u8,
			imp_identity_verified: 8u8,
			imp_some_error: 9u8,

			imp_mock_module: 100u8,
			imp_mock_set_user_shielding_key: 0u8,
			imp_mock_link_identity: 1u8,
			imp_mock_unlink_identity: 2u8,
			imp_mock_verify_identity: 3u8,
			imp_mock_user_shielding_key_set: 4u8,
			imp_mock_challenge_code_generated: 5u8,
			imp_mock_identity_linked: 6u8,
			imp_mock_identity_unlinked: 7u8,
			imp_mock_identity_verified: 8u8,
			imp_mock_some_error: 9u8,
			
			imported_sidechain_block: 0u8,
			runtime_spec_version: 25,
			runtime_transaction_version: 4,
		}
	}
}

impl TeerexCallIndexes for NodeMetadataMock {
	fn register_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.register_enclave])
	}

	fn unregister_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.unregister_enclave])
	}

	fn call_worker_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.call_worker])
	}

	fn confirm_processed_parentchain_block_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.processed_parentchain_block])
	}

	fn shield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.shield_funds])
	}

	fn unshield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.unshield_funds])
	}
}

impl SidechainCallIndexes for NodeMetadataMock {
	fn confirm_imported_sidechain_block_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.sidechain_module, self.imported_sidechain_block])
	}
}

impl IMPCallIndexes for NodeMetadataMock {
	fn set_user_shielding_key_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_set_user_shielding_key])
	}

	fn link_identity_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_link_identity])
	}

	fn unlink_identity_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_unlink_identity])
	}

	fn verify_identity_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_verify_identity])
	}

	fn user_shielding_key_set_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_user_shielding_key_set])
	}

	fn challenge_code_generated_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_challenge_code_generated])
	}

	fn identity_linked_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_identity_linked])
	}

	fn identity_unlinked_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_identity_unlinked])
	}

	fn identity_verified_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_identity_verified])
	}

	fn some_error_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_module, self.imp_some_error])
	}
}

impl IMPMockCallIndexes for NodeMetadataMock {
	fn set_user_shielding_key_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_set_user_shielding_key])
	}

	fn link_identity_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_link_identity])
	}

	fn unlink_identity_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_unlink_identity])
	}

	fn verify_identity_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_verify_identity])
	}

	fn user_shielding_key_set_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_user_shielding_key_set])
	}

	fn challenge_code_generated_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_challenge_code_generated])
	}

	fn identity_linked_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_identity_linked])
	}

	fn identity_unlinked_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_identity_unlinked])
	}

	fn identity_verified_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_identity_verified])
	}

	fn some_error_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.imp_mock_module, self.imp_mock_some_error])
	}
}
