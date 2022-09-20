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

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use codec::{Decode, Encode};
use sp_runtime::{traits::ConstU32, BoundedVec, MultiSignature};
use sp_std::vec::Vec;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct TwitterValidationData {
	pub tweet_id: Vec<u8>,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct DiscordValidationData {
	pub channel_id: Vec<u8>,
	pub message_id: Vec<u8>,
	pub guild_id: Vec<u8>,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Web3CommonValidationData {
	pub message: Vec<u8>, // or String if under std
	                      // pub signature: MultiSignature,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[allow(non_camel_case_types)]
pub enum Web2ValidationData {
	Twitter(TwitterValidationData),
	Discord(DiscordValidationData),
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[allow(non_camel_case_types)]
pub enum Web3ValidationData {
	Substrate(Web3CommonValidationData),
	Evm(Web3CommonValidationData),
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum ValidationData {
	Web2(Web2ValidationData),
	Web3(Web3ValidationData),
}
