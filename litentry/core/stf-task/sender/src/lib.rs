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
// pub mod stf_task_receiver;
// pub mod https_client;
pub use error::Result;

use codec::{Decode, Encode, MaxEncodedLen};
use litentry_primitives::{Identity, Web2ValidationData};

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct Web2IdentityVerificationRequest {
	pub target: AccountId,
	pub identity: Identity,
	pub challenge_code: u32,
	pub validation_data: Web2ValidationData,
	pub bn: litentry_primitives::ParentchainBlockNumber, //Parentchain BlockNumber
}

/// TODO: adapt Web3 struct fields later
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct Web3IdentityVerificationRequest {
	pub target: AccountId,
	pub identity: Identity,
	pub challenge_code: u32,
	pub validation_data: Web2ValidationData,
	pub bn: litentry_primitives::ParentchainBlockNumber, //Parentchain BlockNumber
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct Assertion1Request {
	pub target: AccountId,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct Assertion2Request {
	pub target: AccountId,
	pub identity: Identity,
}

pub enum AssertionType {
	AssertionType1(Assertion1Request), // TODO: The type names can be adapted later
	AssertionType2(Assertion2Request),
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, MaxEncodedLen)]
pub struct SetChallengeCodeRequest {
	pub target: AccountId,
	pub identity: Identity,
	pub challenge_code: u32,
}

pub enum RequestType {
	Web2IdentityVerification(Web2IdentityVerificationRequest),
	Web3IdentityVerification(Web3IdentityVerificationRequest),
	Assertion(AssertionType),
	SetChallengeCode(SetChallengeCodeRequest),
}
