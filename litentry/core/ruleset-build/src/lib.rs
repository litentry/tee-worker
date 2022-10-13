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

use itp_types::AccountId;

use litentry_primitives::{Identity, ParameterString, Ruleset};

pub mod web2;

use crate::web2::ruleset2_verification;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
	#[error("Ruleset error: {0}")]
	Ruleset1Error(String),

	#[error("Other error: {0}")]
	RulesetOtherError(String),
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

pub fn ruleset_verify(who: AccountId, identity: Identity, ruleset: Ruleset) -> Result<()> {
	match ruleset {
		Ruleset::R2(guilt_id, user_id) => ruleset2_verification(who, identity, guilt_id, user_id),
		_ => Ok(()),
	}
}
