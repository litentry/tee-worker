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

//! A pallet to serve as the interface for F/E for verifiable credentials (VC)
//! management. Similar to IMP pallet, the actual processing will be done within TEE.
//
// Note:
// - the admin account can only be set by SetAdminOrigin, which will be bound at runtime.
// TODO: benchmark and weights: we need worst-case scenarios

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unused_variables)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub use pallet::*;
use primitives::{AesOutput, ShardIdentifier};
use sp_core::H256;
use sp_std::vec::Vec;

mod vc_context;
pub use vc_context::*;

mod assertion;
pub use assertion::*;

mod schema;
pub use schema::*;

// fn types for xt handling inside tee-worker
pub type GenerateVCFn = ([u8; 2], ShardIdentifier, u32);

// VCID type in the registry, maybe we want a "did:...." format?
pub type VCID = u64;

pub type SchemaID = u64;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		// some extrinsics should only be called by origins from TEE
		type TEECallOrigin: EnsureOrigin<Self::Origin>;
		/// The origin who can set the admin account
		type SetAdminOrigin: EnsureOrigin<Self::Origin>;
	}

	// a map VCID -> VC context
	#[pallet::storage]
	#[pallet::getter(fn vc_registry)]
	pub type VCRegistry<T: Config> = StorageMap<_, Blake2_256, VCID, VCContext<T>>;

	// the Schema admin account
	#[pallet::storage]
	#[pallet::getter(fn schema_admin)]
	pub type SchemaAdmin<T: Config> = StorageValue<_, T::AccountId>;

	// the Schema contents
	#[pallet::storage]
	#[pallet::getter(fn vc_schema)]
	pub type SchemaRegistry<T: Config> = StorageMap<_, Blake2_256, SchemaID, VCSchema<T>>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		// TODO: do we need account as event parameter? This needs to be decided by F/E
		VCRequested { shard: ShardIdentifier, assertion: Assertion },
		// a VC is disabled on chain
		VCDisabled { id: VCID },
		// a VC is revoked on chain
		VCRevoked { id: VCID },
		// event that should be triggered by TEECallOrigin
		// a VC is just issued
		VCIssued { account: T::AccountId, id: VCID, vc: AesOutput },
		// some error happened during processing in TEE, we use string-like
		// parameters for more "generic" error event reporting
		// TODO: maybe use concrete errors instead of events when we are more sure
		// see also the comment at the beginning
		SomeError { func: Vec<u8>, error: Vec<u8> },

		/// Admin acccount was changed, the \[ old admin \] is provided
		SchemaAdminChanged { old_admin: Option<T::AccountId> },
		// a Schema is issued
		SchemaIssued { account: T::AccountId, id: Vec<u8>, content: Vec<u8> },
		// a Schema is disabled
		SchemaDisable { account: T::AccountId, id: Vec<u8>, content: Vec<u8> },
		// a Schema is revoked
		SchemaRevoked { account: T::AccountId, id: Vec<u8>, content: Vec<u8> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// the VC already exists
		VCAlreadyExists,
		/// the ID doesn't exist
		VCNotExist,
		/// The requester doesn't have the permission (because of subject mismatch)
		VCSubjectMismatch,
		/// The VC is already disabled
		VCAlreadyDisabled,

		/// Error when the caller account is not the admin
		RequireSchemaAdmin,
		/// Schema Id already exists
		SchemaAlreadyExists,
		/// Schema Id not exists
		SchemaNotExists,
		/// new Schema requires Admin
		SchemaRequireAdmin,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(195_000_000)]
		pub fn request_vc(
			origin: OriginFor<T>,
			shard: ShardIdentifier,
			assertion: Assertion,
		) -> DispatchResultWithPostInfo {
			let _ = ensure_signed(origin)?;
			Self::deposit_event(Event::VCRequested { shard, assertion });
			Ok(().into())
		}

		#[pallet::weight(195_000_000)]
		pub fn disable_vc(origin: OriginFor<T>, id: VCID) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;

			VCRegistry::<T>::try_mutate(id, |context| {
				let mut c = context.take().ok_or(Error::<T>::VCNotExist)?;
				ensure!(who == c.subject, Error::<T>::VCSubjectMismatch);
				ensure!(c.status == Status::Active, Error::<T>::VCAlreadyDisabled);
				c.status = Status::Disabled;
				*context = Some(c);
				Self::deposit_event(Event::VCDisabled { id });
				Ok(().into())
			})
		}

		#[pallet::weight(195_000_000)]
		pub fn revoke_vc(origin: OriginFor<T>, id: VCID) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;

			let context = VCRegistry::<T>::get(id).ok_or(Error::<T>::VCNotExist)?;
			ensure!(who == context.subject, Error::<T>::VCSubjectMismatch);
			VCRegistry::<T>::remove(id);
			Self::deposit_event(Event::VCRevoked { id });
			Ok(().into())
		}

		/// ---------------------------------------------------
		/// The following extrinsics are supposed to be called by TEE only
		/// ---------------------------------------------------
		#[pallet::weight(195_000_000)]
		pub fn vc_issued(
			origin: OriginFor<T>,
			account: T::AccountId,
			id: u64,
			hash: H256,
			vc: AesOutput,
		) -> DispatchResultWithPostInfo {
			let _ = T::TEECallOrigin::ensure_origin(origin)?;
			ensure!(!VCRegistry::<T>::contains_key(id), Error::<T>::VCAlreadyExists);
			VCRegistry::<T>::insert(id, VCContext::<T>::new(account.clone(), hash));
			Self::deposit_event(Event::VCIssued { account, id, vc });
			Ok(Pays::No.into())
		}

		#[pallet::weight(195_000_000)]
		pub fn some_error(
			origin: OriginFor<T>,
			func: Vec<u8>,
			error: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			let _ = T::TEECallOrigin::ensure_origin(origin)?;
			Self::deposit_event(Event::SomeError { func, error });
			Ok(Pays::No.into())
		}

		// Change the schema admin account
		#[pallet::weight(195_000_000)]
		pub fn set_admin(origin: OriginFor<T>, new: T::AccountId) -> DispatchResultWithPostInfo {
			T::SetAdminOrigin::ensure_origin(origin)?;
			Self::deposit_event(Event::SchemaAdminChanged { old_admin: Self::schema_admin() });
			<SchemaAdmin<T>>::put(new);
			// Do not pay a fee
			Ok(Pays::No.into())
		}
	}
}