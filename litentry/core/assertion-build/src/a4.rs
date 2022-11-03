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

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use crate::{Error, Result};
use std::{format, string::ToString};

use lc_stf_task_sender::MaxIdentityLength;
use litentry_primitives::{Identity, IdentityWebType, Web3Network};
use sp_runtime::BoundedVec;

use lc_data_providers::graphql_litentry::GraphQLLitentryClient;

pub fn build(identities: BoundedVec<Identity, MaxIdentityLength>) -> Result<()> {
	let mut client = GraphQLLitentryClient::new();

	for identity in identities {
		match identity.web_type {
			IdentityWebType::Web3(_) => client
				.check_lit_holder("0x61f2270153bb68dc0ddb3bc4e4c1bd7522e918ad".as_bytes().to_vec()),
			_ => Ok(()),
		};

		// match client.check_lit_holder() {

		// }
	}

	Err(Error::Assertion4Error("None LIT holder".to_string()))
	// match client.check_id_hubber(guild_id.into_inner(), handler.into_inner()) {
	// 	Err(e) => {
	// 		log::error!("error build assertion4: {:?}", e);
	// 		Err(Error::Assertion3Error(format!("{:?}", e)))
	// 	},
	// 	Ok(_response) => {
	// 		// TODO:
	// 		// generate_vc(who, identity, ...)

	// 		Ok(())
	// 	},
	// }
}

#[cfg(test)]
mod tests {
	use crate::a4::build;
	use frame_support::BoundedVec;
	use log;

	#[test]
	fn assertion4_verification_works() {
		let guildid: u64 = 919848390156767232;
		let guild_id_vec: Vec<u8> = format!("{}", guildid).as_bytes().to_vec();
		let handler_vec: Vec<u8> = "ericzhang.eth#0114".to_string().as_bytes().to_vec();

		let guild_id = BoundedVec::try_from(guild_id_vec).unwrap();
		let handler = BoundedVec::try_from(handler_vec).unwrap();

		let _ = build(guild_id, handler);
		log::info!("assertion3 test");
	}
}
