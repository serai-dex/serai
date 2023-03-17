#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

mod amount;
pub use amount::*;

mod block;
pub use block::*;

mod coins;
pub use coins::*;

mod balance;
pub use balance::*;

mod account;
pub use account::*;

// Monero, our current longest address candidate, has a longest address of featured with payment ID
// 1 (enum) + 1 (flags) + 64 (two keys) + 8 (payment ID) = 74
pub const MAX_ADDRESS_LEN: u32 = 74;

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct ExternalAddress(BoundedVec<u8, ConstU32<{ MAX_ADDRESS_LEN }>>);

#[cfg(feature = "std")]
impl Zeroize for ExternalAddress {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize()
  }
}

impl ExternalAddress {
  #[cfg(feature = "std")]
  pub fn new(address: Vec<u8>) -> Result<ExternalAddress, &'static str> {
    Ok(ExternalAddress(address.try_into().map_err(|_| "address length exceeds {MAX_ADDRESS_LEN}")?))
  }

  pub fn address(&self) -> &[u8] {
    self.0.as_ref()
  }

  #[cfg(feature = "std")]
  pub fn consume(self) -> Vec<u8> {
    self.0.into_inner()
  }
}

impl AsRef<[u8]> for ExternalAddress {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

// Should be enough for a Uniswap v3 call
pub const MAX_DATA_LEN: u32 = 512;
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Data(BoundedVec<u8, ConstU32<{ MAX_DATA_LEN }>>);

#[cfg(feature = "std")]
impl Zeroize for Data {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize()
  }
}

impl Data {
  #[cfg(feature = "std")]
  pub fn new(data: Vec<u8>) -> Result<Data, &'static str> {
    Ok(Data(data.try_into().map_err(|_| "data length exceeds {MAX_DATA_LEN}")?))
  }

  pub fn data(&self) -> &[u8] {
    self.0.as_ref()
  }

  #[cfg(feature = "std")]
  pub fn consume(self) -> Vec<u8> {
    self.0.into_inner()
  }
}

impl AsRef<[u8]> for Data {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}
