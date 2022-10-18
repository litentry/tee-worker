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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{CheckJoinDiscordResponse, Error, Result};

use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet,
};
use std::{format, str, string::String, time::Duration, vec};
use url::Url;

use itp_types::AccountId;

use litentry_primitives::{Identity, ParameterString};

const DISCORD_BASE_URL: &str = "https://47.57.13.126:8080/";
const TIMEOUT: Duration = Duration::from_secs(3u64);

pub fn ruleset2_verification(
	_who: AccountId,
	_identity: Identity,
	guild_id: ParameterString,
	user_id: ParameterString,
) -> Result<()> {
	let base_url = Url::parse(DISCORD_BASE_URL).unwrap();
	let http_client = HttpClient::new(DefaultSend {}, true, Some(TIMEOUT), None, None);
	let mut client = RestClient::new(http_client, base_url);

	let path = format!(
		"/discord/joined?guildid={:?}&userid={:?}",
		guild_id.into_inner(),
		user_id.into_inner()
	);
	let query = vec![];

	let response: CheckJoinDiscordResponse = client
		.get_with::<String, CheckJoinDiscordResponse>(path, query.as_slice())
		.map_err(|e| Error::Ruleset1Error(format!("{:?}", e)))?;

	log::debug!(
		"get response: data: {:?}, message: {:?}, hasError: {:?}, msgCode: {:?}, success: {:?}",
		response.data,
		response.message,
		response.has_errors,
		response.msg_code,
		response.success
	);

	// TODO:
	// generate_vc(who, identity, ...)

	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::discord::ruleset2_verification;
	use frame_support::BoundedVec;
	use itp_types::AccountId;
	use litentry_primitives::{
		Identity, IdentityHandle, IdentityString, IdentityWebType, Web2Network,
	};
	use log;

	#[test]
	fn ruleset2_verification_works() {
		let guildid: u64 = 919848390156767232;
		let userid: u64 = 746308249695027224;
		let guild_id_vec: Vec<u8> = format!("{}", guildid).as_bytes().to_vec();
		let user_id_vec: Vec<u8> = format!("{}", userid).as_bytes().to_vec();

		let guild_id = BoundedVec::try_from(guild_id_vec).unwrap();
		let user_id = BoundedVec::try_from(user_id_vec).unwrap();
		let who = AccountId::from([0; 32]);
		let identity: Identity = Identity {
			web_type: IdentityWebType::Web2(Web2Network::Discord),
			handle: IdentityHandle::String(
				IdentityString::try_from("litentry".as_bytes().to_vec()).unwrap(),
			),
		};
		let _ = ruleset2_verification(who, identity, guild_id, user_id);
		log::info!("ruleset test");
	}
}
