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
use codec::{Decode, Encode};
use sp_std::vec::Vec;

mod ethereum_signature;
mod identity;
mod validation_data;
pub use identity::*;
pub use validation_data::*;
pub use ethereum_signature::*;

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

// deprecated - to be removed
pub type LinkingAccountIndex = u32;

// deprecated - to be removed
pub mod eth {
	pub type EthAddress = [u8; 20];
	pub type EthSignature = [u8; 65];
}
