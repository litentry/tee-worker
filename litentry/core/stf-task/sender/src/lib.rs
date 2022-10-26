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

//! Parentchain block importing logic.
#![feature(trait_alias)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
	pub use url_sgx as url;
}

use itp_types::AccountId;
pub mod error;
pub mod stf_task_sender;
pub use error::Result;

use sp_runtime::{traits::ConstU32, BoundedVec};

use codec::{Decode, Encode, MaxEncodedLen};
use litentry_primitives::{
	Assertion, ChallengeCode, Identity, UserShieldingKeyType, Web2ValidationData,
	Web3ValidationData,
};

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct Web2IdentityVerificationRequest {
	pub who: AccountId,
	pub identity: Identity,
	pub challenge_code: ChallengeCode,
	pub validation_data: Web2ValidationData,
	pub bn: litentry_primitives::ParentchainBlockNumber, //Parentchain BlockNumber
}

/// TODO: adapt Web3 struct fields later
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct Web3IdentityVerificationRequest {
	pub who: AccountId,
	pub identity: Identity,
	pub challenge_code: ChallengeCode,
	pub validation_data: Web3ValidationData,
	pub bn: litentry_primitives::ParentchainBlockNumber, //Parentchain BlockNumber
}

pub type MaxIdentityLength = ConstU32<64>;
/// TODO: adapt struct fields later
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct AssertionBuildRequest {
	pub who: AccountId,
	pub assertion: Assertion,
	pub vec_identity: BoundedVec<Identity, MaxIdentityLength>,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct SetChallengeCodeRequest {
	pub who: AccountId,
	pub identity: Identity,
	pub challenge_code: u32,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct SetUserShieldingKeyRequest {
	pub who: AccountId,
	pub key: UserShieldingKeyType,
}

pub enum RequestType {
	Web2IdentityVerification(Web2IdentityVerificationRequest),
	Web3IdentityVerification(Web3IdentityVerificationRequest),
	AssertionVerification(AssertionBuildRequest),
	SetChallengeCode(SetChallengeCodeRequest),
	// set the user shielding key async - more for demo purpose to
	// show how to read/write the storage in stf-task-receiver
	// we can of course do it synchronously
	SetUserShieldingKey(SetUserShieldingKeyRequest),
}

impl From<Web2IdentityVerificationRequest> for RequestType {
	fn from(r: Web2IdentityVerificationRequest) -> Self {
		RequestType::Web2IdentityVerification(r)
	}
}

impl From<Web3IdentityVerificationRequest> for RequestType {
	fn from(r: Web3IdentityVerificationRequest) -> Self {
		RequestType::Web3IdentityVerification(r)
	}
}

impl From<AssertionBuildRequest> for RequestType {
	fn from(r: AssertionBuildRequest) -> Self {
		RequestType::AssertionVerification(r)
	}
}

impl From<SetChallengeCodeRequest> for RequestType {
	fn from(r: SetChallengeCodeRequest) -> Self {
		RequestType::SetChallengeCode(r)
	}
}

impl From<SetUserShieldingKeyRequest> for RequestType {
	fn from(r: SetUserShieldingKeyRequest) -> Self {
		RequestType::SetUserShieldingKey(r)
	}
}
