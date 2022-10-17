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

use crate::{
	helpers::generate_challenge_code, AccountId, IdentityManagement, MetadataOf, Runtime, StfError,
	StfResult, TrustedCallSigned,
};
use frame_support::dispatch::UnfilteredDispatchable;
use itp_utils::stringify::account_id_to_string;
use lc_stf_task_sender::{
	stf_task_sender::{SendStfRequest, StfRequestSender},
	RequestType, RulesetVerificationRequest, Web2IdentityVerificationRequest,
	Web3IdentityVerificationRequest,
};
use litentry_primitives::{
	ChallengeCode, Identity, IdentityWebType, ParentchainBlockNumber, Ruleset,
	UserShieldingKeyType, ValidationData, Web2Network,
};
use log::*;
use std::{format, string::ToString};

impl TrustedCallSigned {
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
	) -> StfResult<ChallengeCode> {
		debug!(
			"who.str = {:?}, identity = {:?}, metadata = {:?}, bn = {:?}",
			account_id_to_string(&who),
			identity,
			metadata,
			bn
		);

		ita_sgx_runtime::IdentityManagementCall::<Runtime>::link_identity {
			who: who.clone(),
			identity: identity.clone(),
			metadata,
			linking_request_block: bn,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;

		// generate challenge code
		let code = generate_challenge_code();
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::set_challenge_code {
			who,
			identity,
			code,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;

		Ok(code)
	}

	pub fn unlink_identity(who: AccountId, identity: Identity) -> StfResult<()> {
		debug!("who.str = {:?}, identity = {:?}", account_id_to_string(&who), identity,);
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
			identity,
			bn
		);
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::verify_identity {
			who: who.clone(),
			identity: identity.clone(),
			verification_request_block: bn,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;

		// remove challenge code
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::remove_challenge_code { who, identity }
			.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
			.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;

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
					web2_cnt += 1;
				} else if identity_ctx.0.is_web3() {
					web3_cnt += 1;
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

	pub fn verify_ruleset2(who: AccountId, identity: Identity, ruleset: Ruleset) -> StfResult<()> {
		let v_identity_context =
		ita_sgx_runtime::pallet_identity_management::Pallet::<Runtime>::get_identity_and_identity_context(&who);

		for identity_ctx in &v_identity_context {
			if identity_ctx.1.is_verified {
				if identity_ctx.0.web_type == IdentityWebType::Web2(Web2Network::Discord) {
					let request: RequestType =
						RulesetVerificationRequest { who, identity, ruleset }.into();

					let sender = StfRequestSender::new();
					return sender
						.send_stf_request(request)
						.map_err(|_| StfError::VerifyIdentityFailed)
				}
			}
		}
		Ok(())
	}

	pub fn query_credit(_account_id: AccountId) -> StfResult<()> {
		// info!("query_credit({:x?})", account_id.encode(),);
		// let tweet_id: Vec<u8> = "1569510747084050432".as_bytes().to_vec();
		// // let request_str = format!("{}", "https://httpbin.org/anything");
		// let request = lc_stf_task_handler::Request { tweet_id };
		// let sender = lc_stf_task_handler::stf_task_sender::StfRequestSender::new();
		// let result = sender.send_stf_request(request);
		// info!("send https request, get result as {:?}", result);

		Ok(())
	}

	pub fn set_challenge_code(
		account: AccountId,
		identity: Identity,
		code: ChallengeCode,
	) -> StfResult<()> {
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::set_challenge_code {
			who: account,
			identity,
			code,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		Ok(())
	}

	pub fn verify_identity_step1(
		who: AccountId,
		identity: Identity,
		validation_data: ValidationData,
		bn: ParentchainBlockNumber,
	) -> StfResult<()> {
		let code = IdentityManagement::challenge_codes(&who, &identity)
			.ok_or_else(|| StfError::Dispatch("code not found".to_string()))?;

		debug!("who:{:?}, identity:{:?}, code:{:?}", who, identity, code);

		let request: RequestType = match validation_data {
			ValidationData::Web2(web2) => Web2IdentityVerificationRequest {
				who,
				identity,
				challenge_code: code,
				validation_data: web2,
				bn,
			}
			.into(),
			ValidationData::Web3(web3) => Web3IdentityVerificationRequest {
				who,
				identity,
				challenge_code: code,
				validation_data: web3,
				bn,
			}
			.into(),
		};

		let sender = StfRequestSender::new();
		sender.send_stf_request(request).map_err(|_| StfError::VerifyIdentityFailed)
	}
}
