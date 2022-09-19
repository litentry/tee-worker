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
use crate::{AccountId, StfError, StfResult, ENCLAVE_ACCOUNT_KEY};
use aes_gcm::{
	aead::{Aead, KeyInit, Payload},
	Aes256Gcm,
};
use codec::{Decode, Encode};
use itp_storage::{storage_double_map_key, storage_map_key, storage_value_key, StorageHasher};
use itp_utils::stringify::account_id_to_string;
use litentry_primitives::{
	eth::EthAddress, AesOutput, UserShieldingKeyType, USER_SHIELDING_KEY_NONCE_LEN,
};
use log::*;
use pallet_sgx_account_linker::LinkedSubAccount;
use std::prelude::v1::*;

use aes_gcm::{aead::OsRng, AeadCore};

pub fn get_storage_value<V: Decode>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
) -> Option<V> {
	let key = storage_value_key(storage_prefix, storage_key_name);
	get_storage_by_key_hash(key)
}

pub fn get_storage_map<K: Encode, V: Decode + Clone>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
	map_key: &K,
	hasher: &StorageHasher,
) -> Option<V> {
	let key = storage_map_key::<K>(storage_prefix, storage_key_name, map_key, hasher);
	get_storage_by_key_hash(key)
}

pub fn get_storage_double_map<K: Encode, Q: Encode, V: Decode + Clone>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
	first: &K,
	first_hasher: &StorageHasher,
	second: &Q,
	second_hasher: &StorageHasher,
) -> Option<V> {
	let key = storage_double_map_key::<K, Q>(
		storage_prefix,
		storage_key_name,
		first,
		first_hasher,
		second,
		second_hasher,
	);
	get_storage_by_key_hash(key)
}

/// Get value in storage.
pub fn get_storage_by_key_hash<V: Decode>(key: Vec<u8>) -> Option<V> {
	if let Some(value_encoded) = sp_io::storage::get(&key) {
		if let Ok(value) = Decode::decode(&mut value_encoded.as_slice()) {
			Some(value)
		} else {
			error!("could not decode state for key {:x?}", key);
			None
		}
	} else {
		info!("key not found in state {:x?}", key);
		None
	}
}

/// Get the AccountInfo key where the account is stored.
pub fn account_key_hash(account: &AccountId) -> Vec<u8> {
	storage_map_key("System", "Account", account, &StorageHasher::Blake2_128Concat)
}

pub fn enclave_signer_account() -> AccountId {
	get_storage_value("Sudo", ENCLAVE_ACCOUNT_KEY).expect("No enclave account")
}

/// Ensures an account is a registered enclave account.
pub fn ensure_enclave_signer_account(account: &AccountId) -> StfResult<()> {
	let expected_enclave_account = enclave_signer_account();
	if &expected_enclave_account == account {
		Ok(())
	} else {
		error!(
			"Expected enclave account {}, but found {}",
			account_id_to_string(&expected_enclave_account),
			account_id_to_string(account)
		);
		Err(StfError::RequireEnclaveSignerAccount)
	}
}

/// Litentry
pub fn get_user_shielding_key(who: &AccountId) -> Option<UserShieldingKeyType> {
	get_storage_map(
		"IdentityManagement",
		"UserShieldingKeys",
		who,
		&StorageHasher::Blake2_128Concat,
	)
}

pub fn get_linked_ethereum_addresses(who: &AccountId) -> Option<Vec<EthAddress>> {
	get_storage_map("SgxAccountLinker", "EthereumLink", who, &StorageHasher::Blake2_128Concat)
}

pub fn get_linked_substrate_addresses(who: &AccountId) -> Option<Vec<LinkedSubAccount<AccountId>>> {
	get_storage_map("SgxAccountLinker", "SubLink", who, &StorageHasher::Blake2_128Concat)
}

pub fn aes_encrypt_default(key: &UserShieldingKeyType, data: &[u8]) -> AesOutput {
	// it requires "std" but it shouldn't be a problem
	let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
	aes_encrypt(key, data, b"", nonce.into())
}

pub fn aes_encrypt(
	key: &UserShieldingKeyType,
	data: &[u8],
	aad: &[u8],
	nonce: [u8; USER_SHIELDING_KEY_NONCE_LEN],
) -> AesOutput {
	let cipher = Aes256Gcm::new(key.into());
	let payload = Payload { msg: data, aad };
	let ciphertext = cipher.encrypt(&nonce.into(), payload).unwrap();
	AesOutput { ciphertext, aad: aad.to_vec(), nonce }
}
