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

use crate::{stf_sgx_primitives::types::*, AccountId, StfError, StfResult};
#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;
use codec::Encode;
use ita_sgx_runtime::Runtime;
use litentry_primitives::{Identity, IdentityWebType, UserShieldingKeyType, Web2ValidationData};
use log::*;

use crate::helpers;
use itc_https_client_daemon::daemon_sender::SendHttpsRequest;
use itp_storage::StorageHasher;
use itp_utils::stringify::account_id_to_string;
use std::format;
use support::traits::UnfilteredDispatchable;

impl Stf {
	// TODO: refactor the following two methods (is_web2_account & is_web3_account) later
	fn is_web2_account(did: Identity) -> bool {
		match did.web_type {
			IdentityWebType::Web2(_) => true,
			IdentityWebType::Web3(_) => false,
		}
	}

	fn is_web3_account(did: Identity) -> bool {
		match did.web_type {
			IdentityWebType::Web2(_) => false,
			IdentityWebType::Web3(_) => true,
		}
	}

	pub fn set_user_shielding_key(who: AccountId, key: UserShieldingKeyType) -> StfResult<()> {
		debug!("who.str = {:?}, key = {:?}", account_id_to_string(&who), key.clone());
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::set_user_shielding_key { who, key }
			.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
			.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
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

	pub fn query_credit(account_id: AccountId) -> StfResult<()> {
		// info!("query_credit({:x?})", account_id.encode(),);
		// let tweet_id: Vec<u8> = "1569510747084050432".as_bytes().to_vec();
		// // let request_str = format!("{}", "https://httpbin.org/anything");
		// let request = itc_https_client_daemon::Request { tweet_id };
		// let sender = itc_https_client_daemon::daemon_sender::HttpRequestSender::new();
		// let result = sender.send_https_request(request);
		// info!("send https request, get result as {:?}", result);

		Ok(())
	}

	pub fn link_identity(sender: AccountId, account: AccountId, did: Identity) -> StfResult<()> {
		let origin = ita_sgx_runtime::Origin::signed(sender.clone());

		let parentchain_number =
			ita_sgx_runtime::pallet_parentchain::Pallet::<Runtime>::block_number();

		ita_sgx_runtime::IdentityManagementCall::<Runtime>::link_identity {
			who: account,
			did,
			metadata: None,
			linking_request_block: parentchain_number,
		}
		.dispatch_bypass_filter(origin)
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		Ok(())
	}

	pub fn set_challenge_code(
		sender: AccountId,
		account: AccountId,
		did: Identity,
		challenge_code: u32,
	) -> StfResult<()> {
		let origin = ita_sgx_runtime::Origin::signed(sender.clone());

		ita_sgx_runtime::IdentityManagementCall::<Runtime>::set_challenge_code {
			who: account,
			did,
			code: challenge_code,
		}
		.dispatch_bypass_filter(origin)
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		Ok(())
	}

	pub fn prepare_verify_identity(
		_sender: AccountId,
		target: AccountId,
		did: Identity,
		validation_data: Web2ValidationData,
	) -> StfResult<()> {
		let code: Option<u32> = helpers::get_storage_double_map(
			"IdentityManagement",
			"ChallengeCodes",
			&target,
			&StorageHasher::Blake2_128Concat,
			&did,
			&StorageHasher::Blake2_128Concat,
		);
		//TODO change error type
		code.ok_or_else(|| StfError::Dispatch(format!("code not found")))?;
		let request = itc_https_client_daemon::Request {
			target,
			did,
			challenge_code: code.unwrap(),
			validation_data,
		};
		let http_sender = itc_https_client_daemon::daemon_sender::HttpRequestSender::new();
		http_sender.send_https_request(request);
		Ok(())
	}

	pub fn verify_identity(sender: AccountId, account: AccountId, did: Identity) -> StfResult<()> {
		let origin = ita_sgx_runtime::Origin::signed(sender);

		let parentchain_number =
			ita_sgx_runtime::pallet_parentchain::Pallet::<Runtime>::block_number();

		ita_sgx_runtime::IdentityManagementCall::<Runtime>::verify_identity {
			who: account,
			did,
			verification_request_block: parentchain_number,
		}
		.dispatch_bypass_filter(origin)
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		Ok(())
	}
}
