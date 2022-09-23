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

use codec::{Decode, Encode};
use sp_std::vec::Vec;

// TODO: I wasn't able to get litmus-parachain-runtime compiling under `sgx` feature
//       This would affect the the parentchain primitives (re-)import where we can only
//       hardcode types for `sgx` feature or use sgx-runtime primitives.
// d
//       see the type definition in app-libs/stf/src/stf_sgx_primitives.rs too
#[cfg(all(not(feature = "sgx"), feature = "std"))]
pub use my_node_runtime::BlockNumber as ParentchainBlockNumber;
#[cfg(not(feature = "std"))]
pub type ParentchainBlockNumber = u32;

mod ethereum_signature;
mod identity;
mod validation_data;
pub use ethereum_signature::*;
pub use identity::*;
pub use validation_data::*;

// TODO: import the const and struct from the parachain once the code is there
//
// we use 256-bit AES-GCM as user shielding key
pub const USER_SHIELDING_KEY_LEN: usize = 32;
pub const USER_SHIELDING_KEY_NONCE_LEN: usize = 12;
pub const USER_SHIELDING_KEY_TAG_LEN: usize = 16;

pub type UserShieldingKeyType = [u8; USER_SHIELDING_KEY_LEN];

// all-in-one struct containing the encrypted ciphertext with user's
// shielding key and other metadata that is required for decryption
//
// by default a postfix tag is used => last 16 bytes of ciphertext is MAC tag
#[derive(Debug, Default, Clone, Eq, PartialEq, Encode, Decode)]
pub struct AesOutput {
	pub ciphertext: Vec<u8>,
	pub aad: Vec<u8>,
	pub nonce: [u8; USER_SHIELDING_KEY_NONCE_LEN], // IV
}
