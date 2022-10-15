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
	error::Error as HttpError,
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
	fmt::Debug,
	format,
	marker::PhantomData,
	str,
	string::{String, ToString},
	sync::Arc,
	time::Duration,
	vec,
	vec::Vec,
};
use url::Url;

use itp_types::AccountId;

use litentry_primitives::{Identity, ParameterString, Ruleset};

// const TWITTER_BASE_URL: &str = "https://api.twitter.com";
const DISCORD_BASE_URL: &str = "https://47.57.13.126:8080/";
const TIMEOUT: Duration = Duration::from_secs(3u64);

pub fn ruleset2_verification(
	who: AccountId,
	identity: Identity,
	guild_id: ParameterString,
	user_id: ParameterString,
) -> Result<()> {
	// let base_url = "http://47.57.13.126:8080/".to_string();
	let base_url = Url::parse(DISCORD_BASE_URL).unwrap();
	let http_client = HttpClient::new(DefaultSend {}, true, Some(TIMEOUT), None, None);
	let mut client = RestClient::new(http_client, base_url);

	// let guildid: u64 = 919848390156767232;
	// let userid: u64 = 746308249695027224;

	let path = format!(
		"/discord/joined?guildid={:?}&userid={:?}",
		guild_id.into_inner(),
		user_id.into_inner()
	);
	let query = vec![];

	let response: CheckJoinDiscordResponse = client
		.get_with::<String, CheckJoinDiscordResponse>(path, query.as_slice())
		.map_err(|e| Error::Ruleset1Error(format!("{:?}", e)))?;

	log::info!(
		"get response: data: {:?}, message: {:?}, hasError: {:?}, msgCode: {:?}, success: {:?}",
		response.data,
		response.message,
		response.has_errors,
		response.msg_code,
		response.success
	);

	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::discord::ruleset2_verification;
	use log;
	use std::fmt;

	#[test]
	fn ruleset2_verification_works() {
		let guildid: u64 = 919848390156767232;
		let userid: u64 = 746308249695027224;
		let guild_id: Vec<u8> = format!("{}", guildid).as_bytes().to_vec();
		let user_id: Vec<u8> = format!("{}", userid).as_bytes().to_vec();
		ruleset2_verification();
		log::info!("ruleset test");
		let result = 2 + 2;
		assert_eq!(result, 4);
	}
}
