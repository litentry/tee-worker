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

use crate::{Error, IDHubberResponse, Result};

use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPost,
};
use std::{format, str, string::String, time::Duration};
use url::Url;

use litentry_primitives::ParameterString;

const DISCORD_BASE_URL: &str = "https://47.57.13.126:8080/";
const TIMEOUT: Duration = Duration::from_secs(3u64);

pub fn build(guild_id: ParameterString, handler: ParameterString) -> Result<()> {
	let base_url = Url::parse(DISCORD_BASE_URL).unwrap();
	let http_client = HttpClient::new(DefaultSend {}, true, Some(TIMEOUT), None, None);
	let mut client = RestClient::new(http_client, base_url);

	let get_path = format!(
		"/discord/joined?guildid={:?}&handler={:?}",
		guild_id.clone().into_inner(),
		handler.clone().into_inner()
	);

	let get_response: IDHubberResponse = client
		.get::<String, IDHubberResponse>(get_path)
		.map_err(|e| Error::Assertion2Error(format!("{:?}", e)))?;

	log::debug!(
		"get_response: data: {:?}, message: {:?}, hasError: {:?}, msgCode: {:?}, success: {:?}",
		get_response.data,
		get_response.message,
		get_response.has_errors,
		get_response.msg_code,
		get_response.success
	);

	// TODO:
	// generate_vc(who, identity, ...)

	// Assign ID-Hubber role:
	let post_path = format!(
		"/discord/assgin/idhubber?guildid={:?}&handler={:?}",
		guild_id.into_inner(),
		handler.into_inner()
	);

	let dummy_data = IDHubberResponse {
		data: true,
		message: String::from("IDHubber"),
		has_errors: false,
		msg_code: 0,
		success: true,
	};

	let _response = client
		.post::<String, IDHubberResponse>(post_path, &dummy_data)
		.map_err(|e| Error::Assertion2Error(format!("{:?}", e)));

	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::a2::build;
	use frame_support::BoundedVec;
	use log;

	#[test]
	fn assertion2_verification_works() {
		let guildid: u64 = 919848390156767232;
		// let userid: u64 = 746308249695027224;
		let guild_id_vec: Vec<u8> = format!("{}", guildid).as_bytes().to_vec();
		// let user_id_vec: Vec<u8> = format!("{}", userid).as_bytes().to_vec();
		let handler_vec: Vec<u8> = "againstwar%234779".to_string().as_bytes().to_vec();

		let guild_id = BoundedVec::try_from(guild_id_vec).unwrap();
		// let user_id = BoundedVec::try_from(user_id_vec).unwrap();
		let handler = BoundedVec::try_from(handler_vec).unwrap();

		let _ = build(guild_id, handler);
		log::info!("assertion2 test");
	}
}
