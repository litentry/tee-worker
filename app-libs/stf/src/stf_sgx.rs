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

#[cfg(feature = "test")]
use crate::test_genesis::test_genesis_setup;

use crate::{
	helpers::{
		account_data, account_nonce, aes_encrypt_default, enclave_signer_account,
		ensure_enclave_signer_account, ensure_root, get_account_info,
		get_linked_ethereum_addresses, get_linked_substrate_addresses, get_user_shielding_key,
		increment_nonce, root, validate_nonce,
	},
	AccountData, AccountId, Arc, Getter, Index, ParentchainHeader, PublicGetter, ShardIdentifier,
	State, StateTypeDiff, Stf, StfError, StfResult, TrustedCall, TrustedCallSigned, TrustedGetter,
	ENCLAVE_ACCOUNT_KEY,
};
use codec::Encode;
use ita_sgx_runtime::Runtime;
use itp_node_api::metadata::{
	pallet_imp_mock::IMPMockCallIndexes, pallet_teerex::TeerexCallIndexes,
	provider::AccessNodeMetadata,
};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_storage::storage_value_key;
use itp_types::OpaqueCall;
use itp_utils::stringify::account_id_to_string;
use its_state::SidechainSystemExt;
use litentry_primitives::{TwitterValidationData, ValidationData, Web2ValidationData};
use log::*;
use sidechain_primitives::types::{BlockHash, BlockNumber as SidechainBlockNumber, Timestamp};
use sp_io::hashing::blake2_256;
use sp_runtime::MultiAddress;
use std::{format, prelude::v1::*, vec};
use support::traits::UnfilteredDispatchable;

impl Stf {
	pub fn init_state(enclave_account: AccountId) -> State {
		debug!("initializing stf state, account id {}", account_id_to_string(&enclave_account));
		let mut ext = State::new();

		ext.execute_with(|| {
			// do not set genesis for pallets that are meant to be on-chain
			// use get_storage_hashes_to_update instead

			sp_io::storage::set(&storage_value_key("Balances", "TotalIssuance"), &11u128.encode());
			sp_io::storage::set(&storage_value_key("Balances", "CreationFee"), &1u128.encode());
			sp_io::storage::set(&storage_value_key("Balances", "TransferFee"), &1u128.encode());
			sp_io::storage::set(
				&storage_value_key("Balances", "TransactionBaseFee"),
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_value_key("Balances", "TransactionByteFee"),
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_value_key("Balances", "ExistentialDeposit"),
				&1u128.encode(),
			);
		});

		#[cfg(feature = "test")]
		test_genesis_setup(&mut ext);

		ext.execute_with(|| {
			sp_io::storage::set(
				&storage_value_key("Sudo", ENCLAVE_ACCOUNT_KEY),
				&enclave_account.encode(),
			);

			if let Err(e) = Self::create_enclave_self_account(&enclave_account) {
				error!("Failed to initialize the enclave signer account: {:?}", e);
			}
		});

		trace!("Returning updated state: {:?}", ext);
		ext
	}

	pub fn get_state(ext: &mut impl SgxExternalitiesTrait, getter: Getter) -> Option<Vec<u8>> {
		ext.execute_with(|| match getter {
			Getter::trusted(g) => match g.getter {
				TrustedGetter::free_balance(who) =>
					if let Some(info) = get_account_info(&who) {
						debug!("TrustedGetter free_balance");
						debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
						debug!("Account free balance is {}", info.data.free);
						Some(info.data.free.encode())
					} else {
						None
					},
				TrustedGetter::reserved_balance(who) =>
					if let Some(info) = get_account_info(&who) {
						debug!("TrustedGetter reserved_balance");
						debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
						debug!("Account reserved balance is {}", info.data.reserved);
						Some(info.data.reserved.encode())
					} else {
						None
					},
				TrustedGetter::nonce(who) =>
					if let Some(info) = get_account_info(&who) {
						debug!("TrustedGetter nonce");
						debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
						debug!("Account nonce is {}", info.nonce);
						Some(info.nonce.encode())
					} else {
						None
					},
				// litentry
				TrustedGetter::shielding_key(who) =>
					if let Some(key) = get_user_shielding_key(&who) {
						Some(key.encode())
					} else {
						None
					},
				TrustedGetter::linked_ethereum_addresses(who) =>
					if let Some(addresses) = get_linked_ethereum_addresses(&who) {
						debug!(
							"Linked ethereum addresses for {:x?} is {:?}",
							who.encode(),
							addresses
						);
						Some(addresses.encode())
					} else {
						None
					},
				TrustedGetter::linked_substrate_addresses(who) =>
					if let Some(addresses) = get_linked_substrate_addresses(&who) {
						debug!(
							"Linked substrate addresses for {:x?} is {:?}",
							who.encode(),
							addresses
						);
						Some(addresses.encode())
					} else {
						None
					},
			},
			Getter::public(g) => match g {
				PublicGetter::some_value => Some(42u32.encode()),
			},
		})
	}

	pub fn execute<NodeMetadataRepository>(
		ext: &mut impl SgxExternalitiesTrait,
		call: TrustedCallSigned,
		calls: &mut Vec<OpaqueCall>,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> StfResult<()>
	where
		NodeMetadataRepository: AccessNodeMetadata,
		NodeMetadataRepository::MetadataType: TeerexCallIndexes + IMPMockCallIndexes, // TODO: switch to IMPCallIndexes
	{
		let call_hash = blake2_256(&call.encode());
		ext.execute_with(|| {
			let sender = call.call.account().clone();
			validate_nonce(&sender, call.nonce)?;
			match call.call {
				TrustedCall::balance_set_balance(root, who, free_balance, reserved_balance) => {
					ensure_root(root)?;
					debug!(
						"balance_set_balance({}, {}, {})",
						account_id_to_string(&who),
						free_balance,
						reserved_balance
					);
					ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
						who: MultiAddress::Id(who),
						new_free: free_balance,
						new_reserved: reserved_balance,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
					.map_err(|e| {
						StfError::Dispatch(format!("Balance Set Balance error: {:?}", e.error))
					})?;
					Ok(())
				},
				TrustedCall::balance_transfer(from, to, value) => {
					let origin = ita_sgx_runtime::Origin::signed(from.clone());
					debug!(
						"balance_transfer({}, {}, {})",
						account_id_to_string(&from),
						account_id_to_string(&to),
						value
					);
					if let Some(info) = get_account_info(&from) {
						debug!("sender balance is {}", info.data.free);
					} else {
						debug!("sender balance is zero");
					}
					ita_sgx_runtime::BalancesCall::<Runtime>::transfer {
						dest: MultiAddress::Id(to),
						value,
					}
					.dispatch_bypass_filter(origin)
					.map_err(|e| {
						StfError::Dispatch(format!("Balance Transfer error: {:?}", e.error))
					})?;
					Ok(())
				},
				TrustedCall::balance_unshield(account_incognito, beneficiary, value, shard) => {
					debug!(
						"balance_unshield({}, {}, {}, {})",
						account_id_to_string(&account_incognito),
						account_id_to_string(&beneficiary),
						value,
						shard
					);

					Self::unshield_funds(account_incognito, value)?;
					calls.push(OpaqueCall::from_tuple(&(
						node_metadata_repo
							.get_from_metadata(|m| m.unshield_funds_call_indexes())??,
						beneficiary,
						value,
						shard,
						call_hash,
					)));
					Ok(())
				},
				TrustedCall::balance_shield(enclave_account, who, value) => {
					ensure_enclave_signer_account(&enclave_account)?;
					debug!("balance_shield({}, {})", account_id_to_string(&who), value);
					Self::shield_funds(who, value)?;
					Ok(())
				},
				// litentry
				TrustedCall::set_user_shielding_key(root, who, key) => {
					ensure_root(root)?;
					// TODO: switch to IMPCallIndexes
					// TODO: we only checked if the extrinsic dispatch is successful,
					//       is that enough? (i.e. is the state changed already?)
					match Self::set_user_shielding_key(who.clone(), key) {
						Ok(()) => {
							debug!("set_user_shielding_key {} OK", account_id_to_string(&who));
							calls.push(OpaqueCall::from_tuple(&(
								node_metadata_repo.get_from_metadata(|m| {
									m.user_shielding_key_set_call_indexes()
								})??,
								aes_encrypt_default(&key, &who.encode()),
							)));
						},
						Err(err) => {
							debug!(
								"set_user_shielding_key {} error: {}",
								account_id_to_string(&who),
								err
							);
							calls.push(OpaqueCall::from_tuple(&(
								node_metadata_repo
									.get_from_metadata(|m| m.some_error_call_indexes())??,
								"set_user_shielding_key".as_bytes(),
								format!("{:?}", err).as_bytes(),
							)));
						},
					}
					Ok(())
				},
				TrustedCall::link_eth(
					litentry_account,
					account_index,
					eth_address,
					parent_chain_block_number,
					signature,
				) => {
					debug!(
						"link_eth({:x?}, {}, {:?}, {}, {:?})",
						litentry_account.encode(),
						account_index,
						eth_address,
						parent_chain_block_number,
						signature,
					);

					Self::link_eth(
						litentry_account,
						account_index,
						eth_address,
						parent_chain_block_number,
						signature,
					)
				},
				TrustedCall::link_sub(
					account,
					index,
					network_type,
					linked_account,
					expiring_block_number,
					sig,
				) => {
					debug!(
						"link_sub({:x?}, {}, {:?}, {:x?}, {}, {:?})",
						account.encode(),
						index,
						network_type,
						linked_account,
						expiring_block_number,
						sig,
					);

					Self::link_sub(
						account,
						index,
						network_type,
						linked_account,
						expiring_block_number,
						sig,
					)
				},
				TrustedCall::query_credit(account) => {
					debug!("query_credit({:x?}", account.encode(),);

					Self::query_credit(account)
				},
				TrustedCall::link_identity(root, account, did) =>
					Self::link_identity(root, account, did),
				TrustedCall::set_challenge_code(root, account, did, challenge_code) =>
					Self::set_challenge_code(root, account, did, challenge_code),
				TrustedCall::prepare_verify_identity(root, account, did, validation_data) =>
				// TODO support other validation_data
					if let ValidationData::Web2(Web2ValidationData::Twitter(
						TwitterValidationData { ref tweet_id },
					)) = validation_data
					{
						Self::prepare_verify_identity(
							root,
							account,
							did,
							Web2ValidationData::Twitter(TwitterValidationData {
								tweet_id: tweet_id.to_vec(),
							}),
						)
					} else {
						Err(StfError::Dispatch(
							"validation_data only support Web2ValidationData::Twitter".to_string(),
						))
					},
				TrustedCall::verify_identity(root, account, did) =>
					Self::verify_identity(root, account, did),
			}?;
			increment_nonce(&sender);
			Ok(())
		})
	}

	/// Creates valid enclave account with a balance that is above the existential deposit.
	/// !! Requires a root to be set.
	fn create_enclave_self_account(enclave_account: &AccountId) -> StfResult<()> {
		ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
			who: MultiAddress::Id(enclave_account.clone()),
			new_free: 1000,
			new_reserved: 0,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| {
			StfError::Dispatch(format!(
				"Set Balance for enclave signer account error: {:?}",
				e.error
			))
		})
		.map(|_| ())
	}

	fn shield_funds(account: AccountId, amount: u128) -> StfResult<()> {
		match get_account_info(&account) {
			Some(account_info) => ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
				who: MultiAddress::Id(account),
				new_free: account_info.data.free + amount,
				new_reserved: account_info.data.reserved,
			}
			.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
			.map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?,
			None => {
				debug!(
					"Account {} does not exist yet, initializing by setting free balance to {}",
					account_id_to_string(&account),
					amount
				);
				ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
					who: MultiAddress::Id(account),
					new_free: amount,
					new_reserved: 0,
				}
				.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
				.map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?
			},
		};
		Ok(())
	}

	fn unshield_funds(account: AccountId, amount: u128) -> StfResult<()> {
		match get_account_info(&account) {
			Some(account_info) => {
				if account_info.data.free < amount {
					return Err(StfError::MissingFunds)
				}

				ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
					who: MultiAddress::Id(account),
					new_free: account_info.data.free - amount,
					new_reserved: account_info.data.reserved,
				}
				.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
				.map_err(|e| StfError::Dispatch(format!("Unshield funds error: {:?}", e.error)))?;
				Ok(())
			},
			None => Err(StfError::InexistentAccount(account)),
		}
	}

	pub fn update_storage(ext: &mut impl SgxExternalitiesTrait, map_update: &StateTypeDiff) {
		ext.execute_with(|| {
			map_update.iter().for_each(|(k, v)| {
				match v {
					Some(value) => sp_io::storage::set(k, value),
					None => sp_io::storage::clear(k),
				};
			});
		});
	}

	/// Updates the block number, block hash and parent hash of the parentchain block.
	pub fn update_parentchain_block(
		ext: &mut impl SgxExternalitiesTrait,
		header: ParentchainHeader,
	) -> StfResult<()> {
		ext.execute_with(|| {
			ita_sgx_runtime::ParentchainCall::<Runtime>::set_block { header }
				.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
				.map_err(|e| {
					StfError::Dispatch(format!("Update parentchain block error: {:?}", e.error))
				})
		})?;
		Ok(())
	}

	pub fn get_storage_hashes_to_update(call: &TrustedCallSigned) -> Vec<Vec<u8>> {
		let key_hashes = Vec::new();
		match call.call {
			TrustedCall::balance_set_balance(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_transfer(_, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_unshield(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_shield(_, _, _) => debug!("No storage updates needed..."),
			// litentry
			TrustedCall::set_user_shielding_key(..) => debug!("No storage updates needed..."),
			TrustedCall::link_eth(..) => debug!("No storage updates needed..."),
			TrustedCall::link_sub(..) => debug!("No storage updates needed..."),
			TrustedCall::query_credit(..) => debug!("No storage updates needed..."),
			TrustedCall::link_identity(..) => debug!("No storage updates needed..."),
			TrustedCall::set_challenge_code(..) => debug!("No storage updates needed..."),
			TrustedCall::prepare_verify_identity(..) => debug!("No storage updates needed..."),
			TrustedCall::verify_identity(..) => debug!("No storage updates needed..."),
		};
		key_hashes
	}

	pub fn get_storage_hashes_to_update_for_getter(getter: &Getter) -> Vec<Vec<u8>> {
		debug!(
			"No specific storage updates needed for getter. Returning those for on block: {:?}",
			getter
		);
		Self::storage_hashes_to_update_on_block()
	}

	pub fn storage_hashes_to_update_on_block() -> Vec<Vec<u8>> {
		let mut key_hashes = Vec::new();

		// get all shards that are currently registered
		key_hashes.push(shards_key_hash());
		key_hashes
	}

	pub fn get_root(ext: &mut impl SgxExternalitiesTrait) -> AccountId {
		ext.execute_with(|| root())
	}

	pub fn get_enclave_account(ext: &mut impl SgxExternalitiesTrait) -> AccountId {
		ext.execute_with(|| enclave_signer_account())
	}

	pub fn account_nonce(ext: &mut impl SgxExternalitiesTrait, account: &AccountId) -> Index {
		ext.execute_with(|| {
			let nonce = account_nonce(account);
			debug!("Account {} nonce is {}", account_id_to_string(&account), nonce);
			nonce
		})
	}

	pub fn account_data(
		ext: &mut impl SgxExternalitiesTrait,
		account: &AccountId,
	) -> Option<AccountData> {
		ext.execute_with(|| account_data(account))
	}
}

pub fn storage_hashes_to_update_per_shard(_shard: &ShardIdentifier) -> Vec<Vec<u8>> {
	Vec::new()
}

pub fn shards_key_hash() -> Vec<u8> {
	// here you have to point to a storage value containing a Vec of
	// ShardIdentifiers the enclave uses this to autosubscribe to no shards
	vec![]
}

/// Trait extension to simplify sidechain data access from the STF.
///
/// This should be removed when the refactoring of the STF has been done: #269
pub trait SidechainExt {
	/// get the block number of the sidechain state
	fn get_sidechain_block_number<S: SidechainSystemExt>(ext: &S) -> Option<SidechainBlockNumber>;

	/// set the block number of the sidechain state
	fn set_sidechain_block_number<S: SidechainSystemExt>(
		ext: &mut S,
		number: &SidechainBlockNumber,
	);

	/// get the last block hash of the sidechain state
	fn get_last_block_hash<S: SidechainSystemExt>(ext: &S) -> Option<BlockHash>;

	/// set the last block hash of the sidechain state
	fn set_last_block_hash<S: SidechainSystemExt>(ext: &mut S, hash: &BlockHash);

	/// get the timestamp of the sidechain state
	fn get_timestamp<S: SidechainSystemExt>(ext: &S) -> Option<Timestamp>;

	/// set the timestamp of the sidechain state
	fn set_timestamp<S: SidechainSystemExt>(ext: &mut S, timestamp: &Timestamp);
}

impl SidechainExt for Stf {
	fn get_sidechain_block_number<S: SidechainSystemExt>(ext: &S) -> Option<SidechainBlockNumber> {
		ext.get_block_number()
	}

	fn set_sidechain_block_number<S: SidechainSystemExt>(
		ext: &mut S,
		number: &SidechainBlockNumber,
	) {
		ext.set_block_number(number)
	}

	fn get_last_block_hash<S: SidechainSystemExt>(ext: &S) -> Option<BlockHash> {
		ext.get_last_block_hash()
	}

	fn set_last_block_hash<S: SidechainSystemExt>(ext: &mut S, hash: &BlockHash) {
		ext.set_last_block_hash(hash)
	}

	fn get_timestamp<S: SidechainSystemExt>(ext: &S) -> Option<Timestamp> {
		ext.get_timestamp()
	}

	fn set_timestamp<S: SidechainSystemExt>(ext: &mut S, timestamp: &Timestamp) {
		ext.set_timestamp(timestamp)
	}
}
