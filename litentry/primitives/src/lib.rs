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

#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

pub use parentchain_primitives::BlockNumber as ParentchainBlockNumber;

mod ethereum_signature;
mod identity;
mod validation_data;
pub use ethereum_signature::*;
pub use identity::*;
pub use pallet_imp::{
	AesOutput, UserShieldingKeyType, USER_SHIELDING_KEY_LEN, USER_SHIELDING_KEY_NONCE_LEN,
	USER_SHIELDING_KEY_TAG_LEN,
};
pub use validation_data::*;
