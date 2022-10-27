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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{base_url::DISCORD_LITENTRY, build_client, vec_to_string, Error, HttpError};
use http_req::response::Headers;
use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath,
};
use serde::{Deserialize, Serialize};
use std::{
	default::Default,
	format,
	string::{String, ToString},
	vec::Vec,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct DiscordResponse {
	data: bool,
	message: String,
	has_errors: bool,
	msg_code: u32,
	success: bool,
}

impl RestPath<String> for DiscordResponse {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

pub struct DiscordLitentryClient {
	client: RestClient<HttpClient<DefaultSend>>,
}

impl Default for DiscordLitentryClient {
	fn default() -> Self {
		Self::new()
	}
}

impl DiscordLitentryClient {
	pub fn new() -> Self {
		let headers = Headers::new();
		let client = build_client(DISCORD_LITENTRY, headers);
		DiscordLitentryClient { client }
	}

	pub fn check_join(
		&mut self,
		guild_id: Vec<u8>,
		handler: Vec<u8>,
	) -> Result<DiscordResponse, Error> {
		let guild_id_s = vec_to_string(guild_id)?;
		let handler_s = vec_to_string(handler)?;
		let path = "/discord/joined".to_string();
		self.client
			.get_with::<String, DiscordResponse>(
				path,
				&[("guildid", &guild_id_s), ("handler", &handler_s)],
			)
			.map_err(|e| Error::RequestError(format!("{:?}", e)))
	}

	pub fn check_id_hubber(
		&mut self,
		guild_id: Vec<u8>,
		handler: Vec<u8>,
	) -> Result<DiscordResponse, Error> {
		let guild_id_s = vec_to_string(guild_id)?;
		let handler_s = vec_to_string(handler)?;
		let path = "/discord/commented/idhubber".to_string();
		self.client
			.get_with::<String, DiscordResponse>(
				path,
				&[("guildid", &guild_id_s), ("handler", &handler_s)],
			)
			.map_err(|e| Error::RequestError(format!("{:?}", e)))
	}
}

#[cfg(test)]
mod tests {
	use crate::discord_litentry::DiscordLitentryClient;
	use std::vec::Vec;

	#[test]
	fn check_join_work() {
		let guildid: u64 = 919848390156767232;
		let guild_id_vec: Vec<u8> = format!("{}", guildid).as_bytes().to_vec();
		let handler_vec: Vec<u8> = "againstwar%234779".as_bytes().to_vec();

		let mut client = DiscordLitentryClient::new();
		let response = client.check_join(guild_id_vec, handler_vec);

		assert!(response.is_ok(), "check join discord error: {:?}", response);
	}
}
