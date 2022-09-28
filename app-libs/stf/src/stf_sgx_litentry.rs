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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use crate::{stf_sgx_primitives::types::*, AccountId, MetadataOf, Runtime, StfError, StfResult};
use codec::Encode;
use litentry_primitives::{
	Identity, IdentityWebType, ParentchainBlockNumber, UserShieldingKeyType, Web2ValidationData,
};
use log::*;

use crate::helpers;
use itc_https_client_daemon::daemon_sender::SendHttpsRequest;
use itp_storage::StorageHasher;
use itp_utils::stringify::account_id_to_string;
use std::format;
use support::traits::UnfilteredDispatchable;

impl Stf {
	pub fn set_user_shielding_key(who: AccountId, key: UserShieldingKeyType) -> StfResult<()> {
		debug!("who.str = {:?}, key = {:?}", account_id_to_string(&who), key.clone());
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::set_user_shielding_key { who, key }
			.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
			.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		Ok(())
	}

	pub fn link_identity(
		who: AccountId,
		identity: Identity,
		metadata: Option<MetadataOf<Runtime>>,
		bn: ParentchainBlockNumber,
	) -> StfResult<()> {
		debug!(
			"who.str = {:?}, identity = {:?}, metadata = {:?}, bn = {:?}",
			account_id_to_string(&who),
			identity.clone(),
			metadata,
			bn
		);
		// let parentchain_number = ita_sgx_runtime::pallet_parentchain::Pallet::<Runtime>::block_number();
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::link_identity {
			who,
			identity,
			metadata,
			linking_request_block: bn,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		// TODO: generate challenge code
		Ok(())
	}

	pub fn unlink_identity(who: AccountId, identity: Identity) -> StfResult<()> {
		debug!("who.str = {:?}, identity = {:?}", account_id_to_string(&who), identity.clone(),);
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::unlink_identity { who, identity }
			.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
			.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		Ok(())
	}

	pub fn verify_identity(
		who: AccountId,
		identity: Identity,
		bn: ParentchainBlockNumber,
	) -> StfResult<()> {
		debug!(
			"who.str = {:?}, identity = {:?}, bn = {:?}",
			account_id_to_string(&who),
			identity.clone(),
			bn
		);
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::verify_identity {
			who,
			identity,
			verification_request_block: bn,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		// TODO: remove challenge code
		Ok(())
	}

	pub fn verify_ruleset1(who: AccountId) -> StfResult<()> {
		let v_identity_context =
		ita_sgx_runtime::pallet_identity_management::Pallet::<Runtime>::get_identity_and_identity_context(&who);

		let mut web2_cnt = 0;
		let mut web3_cnt = 0;

		for identity_ctx in &v_identity_context {
			if identity_ctx.1.is_verified {
				if identity_ctx.0.is_web2() {
					web2_cnt = web2_cnt + 1;
				} else if identity_ctx.0.is_web3() {
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

	pub fn set_challenge_code(
		sender: AccountId,
		account: AccountId,
		identity: Identity,
		challenge_code: u32,
	) -> StfResult<()> {
		let origin = ita_sgx_runtime::Origin::signed(sender.clone());

		ita_sgx_runtime::IdentityManagementCall::<Runtime>::set_challenge_code {
			who: account,
			identity,
			code: challenge_code,
		}
		.dispatch_bypass_filter(origin)
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		Ok(())
	}

	pub fn verify_identity_step1(
		_sender: AccountId,
		target: AccountId,
		identity: Identity,
		validation_data: Web2ValidationData,
		bn: ParentchainBlockNumber,
	) -> StfResult<()> {
		let code: Option<u32> = helpers::get_storage_double_map(
			"IdentityManagement",
			"ChallengeCodes",
			&target,
			&StorageHasher::Blake2_128Concat,
			&identity,
			&StorageHasher::Blake2_128Concat,
		);
		//TODO change error type
		code.ok_or_else(|| StfError::Dispatch(format!("code not found")))?;
		let request = itc_https_client_daemon::Request {
			target,
			identity,
			challenge_code: code.unwrap(),
			validation_data,
			bn,
		};
		let http_sender = itc_https_client_daemon::daemon_sender::HttpRequestSender::new();
		http_sender.send_https_request(request);
		Ok(())
	}
}
