#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(not(feature = "std"))]
use sp_std::Debug;
use sp_core::{ConstU32, bounded::BoundedVec};

// Monero, our current longest address candidate, has a longest address of featured with payment ID
// 1 (enum) + 1 (flags) + 64 (two keys) + 8 (payment ID) = 74
pub const MAX_ADDRESS_LEN: u32 = 74;
// Should be enough for a Uniswap v3 call
pub const MAX_DATA_LEN: u32 = 512;

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct ExternalAddress(BoundedVec<u8, ConstU32<{ MAX_ADDRESS_LEN }>>);
impl ExternalAddress {
  pub fn new(address: Vec<u8>) -> Result<ExternalAddress, &'static str> {
    Ok(ExternalAddress(address.try_into().map_err(|_| "address length exceeds {MAX_ADDRESS_LEN}")?))
  }

  pub fn address(&self) -> &[u8] {
    self.0.as_ref()
  }

  pub fn consume(self) -> Vec<u8> {
    self.0.into_inner()
  }
}

// Not "in" as "in" is a keyword
mod incoming;
pub use incoming::*;

// Not "out" to match in
mod outgoing;
pub use outgoing::*;

mod shorthand;
pub use shorthand::*;
