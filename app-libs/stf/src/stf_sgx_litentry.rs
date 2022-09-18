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
	helpers::get_parentchain_number, stf_sgx_primitives::types::*, AccountId, StfError, StfResult,
};
#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;
use codec::Encode;
use litentry_primitives::{
	eth::{EthAddress, EthSignature},
	LinkingAccountIndex, UserShieldingKeyType,
};
use log::*;

use crate::{DidOf, MetadataOf, Runtime};
use pallet_sgx_account_linker::{MultiSignature, NetworkType};

use std::{format, str, vec::Vec};
use support::traits::UnfilteredDispatchable;

use itc_https_client_daemon::daemon_sender::SendHttpsRequest;
use itp_utils::stringify::account_id_to_string;

impl Stf {
	// TODO: refactor the following two methods (is_web2_account & is_web3_account) later
	// TODO: - this should go to helpers
	//       - which one is better, a raw string, or a struct?
	fn is_web2_account(did: DidOf<Runtime>) -> bool {
		match str::from_utf8(&did) {
			Ok(v) => {
				let vstr: Vec<&str> = v.split(':').collect();
				if vstr[3] == "web2" {
					return true
				}
			},
			Err(e) => {
				error!("Invalid account bytes: {}", e);
			},
		};

		false
	}

	fn is_web3_account(did: DidOf<Runtime>) -> bool {
		match str::from_utf8(&did) {
			Ok(v) => {
				let vstr: Vec<&str> = v.split(':').collect();
				if vstr[3] == "web3" {
					return true
				}
			},
			Err(e) => {
				error!("Invalid account bytes: {}", e);
			},
		};

		false
	}

	pub fn set_user_shielding_key(who: AccountId, key: UserShieldingKeyType) -> StfResult<()> {
		debug!("who.str = {:?}, key = {:?}", account_id_to_string(&who), key.clone());
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::set_user_shielding_key { who, key }
			.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
			.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		Ok(())
	}

	pub fn link_identity(
		who: AccountId,
		did: DidOf<Runtime>,
		metadta: Option<MetadataOf<Runtime>>,
	) -> StfResult<()> {
		Ok(())
	}

	pub fn verify_ruleset1(who: AccountId) -> StfResult<()> {
		let v_did_context =
		ita_sgx_runtime::pallet_identity_management::Pallet::<Runtime>::get_did_and_identity_context(&who);

		let mut web2_cnt = 0;
		let mut web3_cnt = 0;

		for did_ctx in &v_did_context {
			if did_ctx.1.is_verified {
				if Self::is_web2_account(did_ctx.0.clone()) {
					web2_cnt = web2_cnt + 1;
				} else if Self::is_web3_account(did_ctx.0.clone()) {
					web3_cnt = web3_cnt + 1;
				}
			}
		}

		if web2_cnt > 0 && web3_cnt > 0 {
			// TODO: generate_vc();
			Ok(())
		} else {
			Err(StfError::RuleSet1VerifyFail)
		}
	}

	pub fn link_eth(
		account: AccountId,
		index: LinkingAccountIndex,
		eth_address: EthAddress,
		block_number: BlockNumber,
		signature: EthSignature,
	) -> StfResult<()> {
		debug!(
			"link_eth({:x?}, {:?}, {:?}, {:?}, {:?})",
			account.encode(),
			index,
			eth_address,
			block_number,
			signature
		);

		// set origin from enclave to original user (otherwise pallet throws BadOrigin error)
		let origin = ita_sgx_runtime::Origin::signed(account.clone());

		match get_parentchain_number() {
			Some(number) => {
				ita_sgx_runtime::SgxAccountLinkerCall::<Runtime>::link_eth {
					account,
					index,
					addr_expected: eth_address,
					layer_one_block_number: number,
					expiring_block_number: block_number,
					sig: signature,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
				Ok(())
			},
			None => {
				error!("link_eth blocknumber l1 unavailable");
				Err(StfError::LayerOneNumberUnavailable)
			},
		}
	}

	pub fn link_sub(
		account: AccountId,
		index: LinkingAccountIndex,
		network_type: NetworkType,
		linked_account: AccountId,
		block_number: BlockNumber,
		signature: MultiSignature,
	) -> StfResult<()> {
		debug!(
			"link_sub({:x?}, {:?}, {:?}, {:x?}, {:?}), {:?})",
			account.encode(),
			index,
			network_type,
			linked_account.encode(),
			block_number,
			signature
		);

		// set origin from enclave to original user (otherwise pallet throws BadOrigin error)
		let origin = ita_sgx_runtime::Origin::signed(account.clone());

		match get_parentchain_number() {
			Some(number) => {
				ita_sgx_runtime::SgxAccountLinkerCall::<Runtime>::link_sub {
					account,
					index,
					network_type,
					linked_account,
					layer_one_block_number: number,
					expiring_block_number: block_number,
					sig: signature,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
				Ok(())
			},
			None => {
				error!("link_sub blocknumber l1 unavailable");
				Err(StfError::LayerOneNumberUnavailable)
			},
		}
	}

	pub fn query_credit(account_id: AccountId) -> StfResult<()> {
		info!("query_credit({:x?})", account_id.encode(),);

		let request_str = format!("{}", "https://httpbin.org/anything");
		let request = itc_https_client_daemon::Request { account_id, request_str };
		let sender = itc_https_client_daemon::daemon_sender::HttpRequestSender::new();
		let result = sender.send_https_request(request);
		info!("send https request, get result as {:?}", result);

		Ok(())
	}
}
