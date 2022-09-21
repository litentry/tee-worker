/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

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
pub struct PrepareVerifyIdentityCommand {
	/// AccountId in ss58check format
	account: String,
	did: String,
	validation_data: String,
}

impl PrepareVerifyIdentityCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedArgs) {
		let who = get_accountid_from_str(&self.account);
		let root = get_pair_from_str(trusted_args, "//Alice");

		let (mrenclave, shard) = get_identifiers(trusted_args);
		let nonce = get_layer_two_nonce!(root, cli, trusted_args);
		// compose the extrinsic
		let validation_data = serde_json::from_str(self.validation_data.as_str());
		if let Err(e) = validation_data {
			warn!("Deserialize ValidationData error: {:?}", e.to_string());
			return
		}
		let identity = serde_json::from_str(self.did.as_str());
		if let Err(e) = identity {
			warn!("Deserialize Identity error: {:?}", e.to_string());
			return
		}
		let top: TrustedOperation = TrustedCall::prepare_verify_identity(
			root.public().into(),
			who,
			identity.unwrap(),
			validation_data.unwrap(),
		)
		.sign(&KeyPair::Sr25519(root), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);
		let _ = perform_trusted_operation(cli, trusted_args, &top);
	}
}
