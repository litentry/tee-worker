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

use crate::{base_url::GRAPHQL_LITENTRY, build_client, vec_to_string, Error, HttpError};
use http_req::response::Headers;
use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath, RestPost,
};
use serde::{Deserialize, Serialize};
use std::{
	default::Default,
	format,
	string::{String, ToString},
	vec::Vec,
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LITHolderResponse {
	data: bool,
}

impl RestPath<String> for LITHolderResponse {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

pub struct GraphQLLitentryClient {
	client: RestClient<HttpClient<DefaultSend>>,
}

impl Default for GraphQLLitentryClient {
	fn default() -> Self {
		Self::new()
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GraphQLQuery {
	query: String,
}
impl RestPath<String> for GraphQLQuery {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GraphQLResponse<T> {
	data: T,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifiedCredentialsIsHodler {
	is_hodler: bool,
}

impl GraphQLLitentryClient {
	pub fn new() -> Self {
		let headers = Headers::new();
		let client = build_client(GRAPHQL_LITENTRY, headers);
		GraphQLLitentryClient { client }
	}

	pub fn check_lit_holder(&mut self, address: Vec<u8>) -> Result<(), Error> {
		let path = "/latest/graphql".to_string();
		let query = GraphQLQuery {
			query: format!(
				"query{{VerifiedCredentialsIsHodler( \
				addresses: [\"0x61f2270153bb68dc0ddb3bc4e4c1bd7522e918ad\"], \
				fromDate:\"2022-10-16T00:00:00Z\", \
				network: ethereum, \
				tokenAddress:\"0xb59490aB09A0f526Cc7305822aC65f2Ab12f9723\" \
				minimumBalance: 0.00000057 \
			  ){{isHodler}} }}"
			),
		};

		let response = self.client
			.post_capture::<String, GraphQLQuery, GraphQLResponse<VerifiedCredentialsIsHodler>>(
				path, &query,
			)
			.map_err(|e| Error::RequestError(format!("{:?}", e)))?;

		println!("response: {:?}", response.data);

		Ok(())
	}

}

#[cfg(test)]
mod tests {
	use crate::graphql_litentry::GraphQLLitentryClient;
	use std::vec::Vec;

	#[test]
	fn check_lit_holder_work() {

		let mut client = GraphQLLitentryClient::new();
		let response = client.check_lit_holder("0x61f2270153bb68dc0ddb3bc4e4c1bd7522e918ad".as_bytes().to_vec());

		println!("response: {:?}", response);
		assert!(response.is_ok(), "check join discord error: {:?}", response);
	}

}
