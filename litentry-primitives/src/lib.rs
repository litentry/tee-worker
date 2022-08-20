//! litentry primitives. It is strictly `no_std`

#![no_std]

// FIXME: is this the right place for this definition?
//        @Han: Yes it's the correct place.
pub type LinkingAccountIndex = u32;

pub mod eth {
	// FIXME: these should be imported from a general crate (currently defined in the account linker pallet)
	//        @Han: This is a good point. We need to have a primitive crate outside worker
	pub type EthAddress = [u8; 20];
	// rsv signature
	pub type EthSignature = [u8; 65];
}
