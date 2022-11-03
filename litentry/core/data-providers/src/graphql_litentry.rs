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
use http::header::CONNECTION;
use http_req::response::Headers;
use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath, RestPost,
};
use serde::{Deserialize, Serialize};
use std::{
	collections::HashMap,
	default::Default,
	format,
	string::{String, ToString},
	vec::Vec,
};

// #[derive(Serialize, Deserialize, Debug)]
// #[serde(rename_all = "camelCase")]
// pub struct LITHolderResponse {
// 	data: bool,
// }
// impl RestPath<String> for LITHolderResponse {
// 	fn get_path(path: String) -> core::result::Result<String, HttpError> {
// 		Ok(path)
// 	}
// }

pub struct GraphQLLitentryClient {
	client: RestClient<HttpClient<DefaultSend>>,
}

impl Default for GraphQLLitentryClient {
	fn default() -> Self {
		Self::new()
	}
}

// #[derive(Serialize, Deserialize, Debug)]
// pub struct GraphQLQuery {
// 	query: String,
// }
// impl RestPath<String> for GraphQLQuery {
// 	fn get_path(path: String) -> core::result::Result<String, HttpError> {
// 		Ok(path)
// 	}
// }
// #[derive(Serialize, Deserialize, Debug)]
// pub struct GraphQLResponse<T> {
// 	data: T,
// }
// impl<T> RestPath<String> for GraphQLResponse<T> {
// 	fn get_path(path: String) -> core::result::Result<String, HttpError> {
// 		Ok(path)
// 	}
// }
// #[derive(Serialize, Deserialize, Debug)]
// pub struct VerifiedCredentialsIsHodler {
// 	is_hodler: bool,
// }

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QLResponse {
	#[serde(flatten)]
	extra: HashMap<String, serde_json::Value>,
}
impl RestPath<String> for QLResponse {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

// #[derive(Serialize, Deserialize, Debug)]
// #[serde(rename_all = "camelCase")]
// pub struct VIsHolder {
// 	verified_credentials_is_hodler: Vec<Holder>,
// }
// impl RestPath<String> for VIsHolder {
// 	fn get_path(path: String) -> core::result::Result<String, HttpError> {
// 		Ok(path)
// 	}
// }
// #[derive(Serialize, Deserialize, Debug)]
// #[serde(rename_all = "camelCase")]
// pub struct Holder {
// 	is_hodler: bool,
// }
// impl RestPath<String> for Holder {
// 	fn get_path(path: String) -> core::result::Result<String, HttpError> {
// 		Ok(path)
// 	}
// }

impl GraphQLLitentryClient {
	pub fn new() -> Self {
		let mut headers = Headers::new();
		headers.insert(CONNECTION.as_str(), "close");
		let client = build_client(GRAPHQL_LITENTRY, headers);
		GraphQLLitentryClient { client }
	}

	pub fn check_lit_holder(&mut self, address: Vec<u8>) -> Result<(), Error> {
		// let path = "/latest/graphql".to_string();
		let path = r#"latest/graphql?query=query%7BVerifiedCredentialsIsHodler(%0A%20%20addresses%3A%20%5B%220x61f2270153bb68dc0ddb3bc4e4c1bd7522e918ad%22%5D%2C%20%0A%20%20fromDate%3A%222022-10-16T00%3A00%3A00Z%22%2C%0A%20%20network%3A%20ethereum%2C%0A%20%20tokenAddress%3A%220xb59490aB09A0f526Cc7305822aC65f2Ab12f9723%22%0A%20%20minimumBalance%3A%200.00000056%0A)%7BisHodler%7D%7D%0A"#;
		// let query = GraphQLQuery {
		// 	query: format!(
		// 		"query{{VerifiedCredentialsIsHodler( \
		// 		addresses: [\"0x61f2270153bb68dc0ddb3bc4e4c1bd7522e918ad\"], \
		// 		fromDate:\"2022-10-16T00:00:00Z\", \
		// 		network: ethereum, \
		// 		tokenAddress:\"0xb59490aB09A0f526Cc7305822aC65f2Ab12f9723\" \
		// 		minimumBalance: 0.00000057 \
		// 	  ){{isHodler}} }}"
		// 	),
		// };

		let response = self.client
			.get_with::<String, QLResponse>(
				//path, &[("query", r#"query%7BVerifiedCredentialsIsHodler(%0A%20%20addresses%3A%20%5B"0x61f2270153bb68dc0ddb3bc4e4c1bd7522e918ad"%5D%2C%20%0A%20%20fromDate%3A"2022-10-16T00%3A00%3A00Z"%2C%0A%20%20network%3A%20ethereum%2C%0A%20%20tokenAddress%3A"0xb59490aB09A0f526Cc7305822aC65f2Ab12f9723"%0A%20%20minimumBalance%3A%200.00000057%0A)%7BisHodler%2C%20address%7D%7D%0A"#)],
				path.to_string(), vec![].as_slice(),
			)
			.map_err(|e| Error::RequestError(format!("{:?}", e)))?;

		println!("function response: {:?}", response);

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
		let response = client
			.check_lit_holder("0x61f2270153bb68dc0ddb3bc4e4c1bd7522e918ad".as_bytes().to_vec());

		println!("test response: {:?}", response);
		// assert!(response.is_ok(), "check lit holder error: {:?}", response);
	}
}
