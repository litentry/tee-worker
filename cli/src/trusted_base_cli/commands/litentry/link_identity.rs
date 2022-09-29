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

use crate::{
	get_layer_two_nonce,
	trusted_command_utils::{get_accountid_from_str, get_identifiers, get_pair_from_str},
	trusted_commands::TrustedArgs,
	trusted_operation::perform_trusted_operation,
	Cli,
};
use codec::Decode;
use ita_stf::{Index, KeyPair, TrustedCall, TrustedGetter, TrustedOperation};
use log::*;
use sp_core::Pair;

#[derive(Parser)]
pub struct LinkIdentityCommand {
	/// AccountId in ss58check format
	account: String,
	did: String,
}

impl LinkIdentityCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedArgs) {
		println!("account = {:?}", self.account);
		let who = get_accountid_from_str(&self.account);
		let root = get_pair_from_str(trusted_args, "//Alice");

		let (mrenclave, shard) = get_identifiers(trusted_args);
		let nonce = get_layer_two_nonce!(root, cli, trusted_args);
		// compose the extrinsic
		let identity = serde_json::from_str(self.did.as_str());
		if let Err(e) = identity {
			warn!("Deserialize Identity error: {:?}", e.to_string());
			return
		}
		let top: TrustedOperation =
			//TODO adjust link_identity
			TrustedCall::link_identity(root.public().into(), who, identity.unwrap(), None, 32)
				.sign(&KeyPair::Sr25519(root), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct);
		let _ = perform_trusted_operation(cli, trusted_args, &top);
	}
}
