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
use crate::{
	build_client_with_authorization, format, str, vec, DecryptionVerificationPayload, Error,
	String, ToString, UserInfo, Vec, VerifyContext, VerifyHandler, MakeClient,
};


use lc_stf_task_sender::{ Web3IdentityVerificationRequest,  };


#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct Web3IdentityVerification<T> {
	pub verification_request: Web3IdentityVerificationRequest,
	pub _marker: PhantomData<T>,
}


impl<R> MakeClient for Web3IdentityVerification<R> {
	type Client = StfDefaultHttpClient;

	fn make_client(&self) -> Result<Self::Client, Error> {

	}
}
