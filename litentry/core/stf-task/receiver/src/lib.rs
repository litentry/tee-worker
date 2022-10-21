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
use ita_stf::{AccountId, Hash, ShardIdentifier, TrustedCall, TrustedOperation};
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_executor::traits::{StfEnclaveSigning, StfExecuteGenericUpdate};
use itp_top_pool_author::traits::AuthorApi;
use litentry_primitives::{Identity, ParentchainBlockNumber};
use std::{fmt::Debug, format, string::String, sync::Arc};

use std::boxed::Box;

#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
	#[error("Request error: {0}")]
	RequestError(String),

	#[error("Ruleset error: {0}")]
	RulesetError(String),

	#[error("Other error: {0}")]
	OtherError(String),
}

pub mod stf_task_receiver;

#[allow(dead_code)]
pub struct StfTaskContext<
	K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
	A: AuthorApi<Hash, Hash>,
	S: StfEnclaveSigning,
	E: StfExecuteGenericUpdate,
> {
	shard: ShardIdentifier,
	shielding_key: K,
	author_api: Arc<A>,
	enclave_signer: Arc<S>,
	pub stf_executor: Arc<E>,
}

impl<
		K: ShieldingCryptoDecrypt + ShieldingCryptoEncrypt + Clone,
		A: AuthorApi<Hash, Hash>,
		S: StfEnclaveSigning,
		E: StfExecuteGenericUpdate,
	> StfTaskContext<K, A, S, E>
{
	pub fn new(
		shard: ShardIdentifier,
		shielding_key: K,
		author_api: Arc<A>,
		enclave_signer: Arc<S>,
		stf_executor: Arc<E>,
	) -> Self {
		Self { shard, shielding_key, author_api, enclave_signer, stf_executor }
	}

	pub fn submit_trusted_call(&self, trusted_call: &TrustedCall) -> Result<(), Error> {
		let signed_trusted_call = self
			.enclave_signer
			.sign_call_with_self(trusted_call, &self.shard)
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

		let trusted_operation = TrustedOperation::indirect_call(signed_trusted_call);

		let encrypted_trusted_call = self
			.shielding_key
			.encrypt(&trusted_operation.encode())
			.map_err(|e| Error::OtherError(format!("{:?}", e)))?;

		let top_submit_future =
			async { self.author_api.submit_top(encrypted_trusted_call, self.shard).await };
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

	// directly read or write the state associated with stf_executor
	// you simply provide `read_or_update_function` that encapsulates the
	// actual business logic.
	//
	// TODO: is it the best form that we can do?
	pub fn read_or_update_state<F, R>(&self, read_or_update_function: F) -> Result<R, Error>
	where
		F: FnOnce() -> Result<R, Error>,
	{
		let inner_fn: Box<dyn FnOnce(E::Externalities) -> Result<(E::Externalities, R), Error>> =
			Box::new(|mut ext| {
				let r = ext.execute_with(read_or_update_function)?;
				Ok((ext, r))
			});
		let (r, _) = E::execute_update::<_, _, Error>(&self.stf_executor, &self.shard, inner_fn)
			.map_err(|e| Error::OtherError(format!("Error read_or_update_state: {:?}", e)))?;
		Ok(r)
	}
}
