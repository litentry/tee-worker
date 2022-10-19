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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
	pub use url_sgx as url;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use itc_rest_client::{error::Error as HttpError, RestPath};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, str, string::String};

pub mod assertion1;
pub mod assertion2;

pub use crate::{assertion1::build_assertion1, assertion2::build_assertion2};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
	#[error("Assertion error: {0}")]
	Assertion1Error(String),

	#[error("Assertion error: {0}")]
	Assertion2Error(String),

	#[error("Other error: {0}")]
	AssertionOtherError(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CheckJoinDiscordResponse {
	data: bool,
	message: String,
	has_errors: bool,
	msg_code: u32,
	success: bool,
}

impl RestPath<String> for CheckJoinDiscordResponse {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}
