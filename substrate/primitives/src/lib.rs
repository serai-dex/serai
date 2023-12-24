#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use sp_core::{ConstU32, bounded::BoundedVec};

pub use sp_application_crypto as crypto;

mod amount;
pub use amount::*;

mod block;
pub use block::*;

mod networks;
pub use networks::*;

mod balance;
pub use balance::*;

mod account;
pub use account::*;

mod tx;
pub use tx::*;

#[cfg(feature = "borsh")]
pub fn borsh_serialize_bounded_vec<W: borsh::io::Write, T: BorshSerialize, const B: u32>(
  bounded: &BoundedVec<T, ConstU32<B>>,
  writer: &mut W,
) -> Result<(), borsh::io::Error> {
  borsh::BorshSerialize::serialize(bounded.as_slice(), writer)
}

#[cfg(feature = "borsh")]
pub fn borsh_deserialize_bounded_vec<R: borsh::io::Read, T: BorshDeserialize, const B: u32>(
  reader: &mut R,
) -> Result<BoundedVec<T, ConstU32<B>>, borsh::io::Error> {
  let vec: Vec<T> = borsh::BorshDeserialize::deserialize_reader(reader)?;
  vec.try_into().map_err(|_| borsh::io::Error::other("bound exceeded"))
}

// Monero, our current longest address candidate, has a longest address of featured
// 1 (enum) + 1 (flags) + 64 (two keys) = 66
// When JAMTIS arrives, it'll become 112 or potentially even 142 bytes
pub const MAX_ADDRESS_LEN: u32 = 196;

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExternalAddress(
  #[cfg_attr(
    feature = "borsh",
    borsh(
      serialize_with = "borsh_serialize_bounded_vec",
      deserialize_with = "borsh_deserialize_bounded_vec"
    )
  )]
  BoundedVec<u8, ConstU32<{ MAX_ADDRESS_LEN }>>,
);
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
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Data(
  #[cfg_attr(
    feature = "borsh",
    borsh(
      serialize_with = "borsh_serialize_bounded_vec",
      deserialize_with = "borsh_deserialize_bounded_vec"
    )
  )]
  BoundedVec<u8, ConstU32<{ MAX_DATA_LEN }>>,
);

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

/// Lexicographically reverses a given byte array.
pub fn reverse_lexicographic_order<const N: usize>(bytes: [u8; N]) -> [u8; N] {
  let mut res = [0u8; N];
  for (i, byte) in bytes.iter().enumerate() {
    res[i] = !*byte;
  }
  res
}

pub type BlockNumber = u64;
pub type Header = sp_runtime::generic::Header<BlockNumber, sp_runtime::traits::BlakeTwo256>;
