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

//! Autogenerated weights for pallet_identity_management
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2022-08-08, STEPS: `20`, REPEAT: 50, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("litmus-dev"), DB CACHE: 20

// Executed Command:
// ./target/release/litentry-collator
// benchmark
// pallet
// --chain=litmus-dev
// --execution=wasm
// --db-cache=20
// --wasm-execution=compiled
// --pallet=pallet_identity_management
// --extrinsic=*
// --heap-pages=4096
// --steps=20
// --repeat=50
// --header=./LICENSE_HEADER
// --template=./templates/benchmark/pallet-weight-template.hbs
// --output=./pallets/identity-management/src/weights.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(clippy::unnecessary_cast)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_identity_management.
pub trait WeightInfo {
	fn link_identity() -> Weight;
	fn unlink_identity() -> Weight;
	fn verify_identity() -> Weight;
	fn set_user_shielding_key() -> Weight;
}

/// Weights for pallet_identity_management using the Litentry node and recommended hardware.
pub struct LitentryWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for LitentryWeight<T> {
	fn link_identity() -> Weight {
		Weight::from_ref_time(17_000_000 as u64)
	}
	fn unlink_identity() -> Weight {
		Weight::from_ref_time(17_000_000 as u64)
	}
	fn verify_identity() -> Weight {
		Weight::from_ref_time(16_000_000 as u64)
	}
	fn set_user_shielding_key() -> Weight {
		Weight::from_ref_time(17_000_000 as u64)
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	fn link_identity() -> Weight {
		Weight::from_ref_time(17_000_000 as u64)
	}
	fn unlink_identity() -> Weight {
		Weight::from_ref_time(17_000_000 as u64)
	}
	fn verify_identity() -> Weight {
		Weight::from_ref_time(16_000_000 as u64)
	}
	fn set_user_shielding_key() -> Weight {
		Weight::from_ref_time(17_000_000 as u64)
	}
}