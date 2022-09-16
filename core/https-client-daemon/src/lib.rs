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

//! Parentchain block importing logic.
#![feature(trait_alias)]
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
use http_sgx as http;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use http_req_sgx as http_req;

use itp_types::AccountId;
pub mod daemon_sender;
pub mod error;
pub mod https_client;
pub use error::Result;
use http_req::{request::Method, response::Headers};
use itc_rest_client::Query;
use std::{string::String, vec::Vec};

pub struct Request {
	pub target: AccountId,
	// pub base_url: Vec<u8>,
	// pub path: Vec<u8>,
	// pub method: Method,
	// pub headers: Headers,
	pub query: Option<Vec<(Vec<u8>, Vec<u8>)>>, // vec<(key, value)>
	// pub body: Option<Vec<u8>>,
	pub handlerType: litentry_primitives::RequestHandlerType,
	// pub tweet_id: Vec<u8>,
}
