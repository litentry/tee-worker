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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use futures_sgx as futures;
	pub use hex_sgx as hex;
	pub use thiserror_sgx as thiserror;
	pub use url_sgx as url;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

use codec::Encode;
use futures::executor;
use ita_stf::{AccountId, Hash, ShardIdentifier, State as StfState, TrustedCall, TrustedOperation};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_stf_executor::traits::StfEnclaveSigning;
use itp_top_pool_author::traits::AuthorApi;
use litentry_primitives::{Identity, ParentchainBlockNumber};
use std::{format, string::String, sync::Arc};

#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
	#[error("Request error: {0}")]
	RequestError(String),

	#[error("Other error: {0}")]
	OtherError(String),
}

pub mod stf_task_receiver;

#[allow(dead_code)]
pub struct StfTaskContext<
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
> {
	shielding_key: K,
	stf_state: Arc<StfState>,
	shard_identifier: ShardIdentifier,
	enclave_signer: Arc<S>,
	author_api: Arc<A>,
}

impl<
		K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
		A: AuthorApi<Hash, Hash>,
		S: StfEnclaveSigning,
	> StfTaskContext<K, A, S>
{
	pub fn new(
		shard_identifier: ShardIdentifier,
		stf_state: Arc<StfState>,
		shielding_key: K,
		enclave_signer: Arc<S>,
		author_api: Arc<A>,
	) -> Self {
		Self { shard_identifier, stf_state, shielding_key, enclave_signer, author_api }
	}

	pub fn submit_trusted_call<'a>(&self, trusted_call: &'a TrustedCall) -> Result<(), Error> {
		let signed_trusted_call = self
			.enclave_signer
			.sign_call_with_self(trusted_call, &self.shard_identifier)
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

		let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);

		let encrypted_trusted_call = self
			.shielding_key
			.encrypt(&trusted_operation.encode())
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

		let top_submit_future = async {
			self.author_api.submit_top(encrypted_trusted_call, self.shard_identifier).await
		};
		executor::block_on(top_submit_future).map_err(|e| {
			Error::OtherError(format!("Error adding indirect trusted call to TOP pool: {:?}", e))
		})?;

		Ok(())
	}

	pub fn create_verify_identity_trusted_call(
		&self,
		who: AccountId,
		identity: Identity,
		bn: ParentchainBlockNumber,
	) -> Result<TrustedCall, Error> {
		let enclave_account_id = self
			.enclave_signer
			.get_enclave_account()
			.map_err(|e| Error::OtherError(format!("Error get enclave signer: {:?}", e)))?;

		Ok(TrustedCall::verify_identity_step2(enclave_account_id, who, identity, bn))
	}
}
