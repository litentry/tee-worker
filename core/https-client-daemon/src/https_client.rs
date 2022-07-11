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

use crate::{
	error::{Error, Result},
	Request,
};
use itc_rest_client::{
	error::Error as HttpError, http_client::HttpClient, rest_client::RestClient, RestGet, RestPath,
};
use itp_extrinsics_factory::CreateExtrinsics;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_types::OpaqueCall;
use log::*;
use serde::{Deserialize, Serialize};
use std::{string::String, time::Duration, vec::Vec};
use url::Url;

const TIMEOUT: Duration = Duration::from_secs(3u64);

/// Https rest client. Handles the https requests and responses.
pub struct HttpsRestClient<T: EnclaveOnChainOCallApi, S: CreateExtrinsics> {
	url: Url,
	client: RestClient<HttpClient>,
	ocall_api: T,
	create_extrinsics: S,
}

// TODO: restructure this
#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseBody {
	pub args: Vec<String>,
	pub origin: String,
	pub url: String,
}

impl RestPath<String> for ResponseBody {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

impl<T: EnclaveOnChainOCallApi, S: CreateExtrinsics> HttpsRestClient<T, S> {
	pub fn new(url: Url, ocall_api: T, create_extrinsics: S) -> Self {
		let http_client = HttpClient::new(true, Some(TIMEOUT), None, None);
		let rest_client = RestClient::new(http_client, url.clone());
		Self { url, client: rest_client, ocall_api, create_extrinsics }
	}

	pub fn base_url(&self) -> &Url {
		&self.url
	}

	/// Sends an https request to the specified server.
	pub fn send(&mut self, request: Request) -> Result<()> {
		let response = self
			.client
			.get::<String, ResponseBody>(request.request_str)
			.map_err(|e| Error::Other(e.into()))?;

		error!("https get result as ( {:?},)", response);

		// TODO: rewrite this, potentially restructure/refactor
		//       additionally, litentry-parachain doesn't have such module/method anyway
		// let hardcode_score = 1234_u32;

		let credit_score_module_id = 64;
		let report_credit_score_method_id = 0;

		let call = OpaqueCall::from_tuple(&(
			[credit_score_module_id, report_credit_score_method_id],
			request.account_id,
		));
		let calls = std::vec![call];

		let tx = self
			.create_extrinsics
			.create_extrinsics(calls.as_slice(), None)
			.map_err(|_| Error::FailedCreateExtrinsic)?;

		let result =
			self.ocall_api.send_to_parentchain(tx).map_err(|_| Error::FailedSendExtrinsic)?;
		error!("https daemon send tx result as ( {:?},)", result);

		Ok(())
	}
}
