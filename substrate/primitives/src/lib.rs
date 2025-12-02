#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;
extern crate alloc;

use zeroize::Zeroize;
use ::borsh::{BorshSerialize, BorshDeserialize};

/// Wrappers to implement Borsh on non-Borsh-implementing types.
#[doc(hidden)]
pub mod sp_borsh;
pub(crate) use sp_borsh::*;

/// Constants within the Serai protocol.
pub mod constants;

/// Cryptographic types.
pub mod crypto;

/// Address types.
pub mod address;

/// Types for identifying coins.
pub mod coin;

/// The `Amount`, `ExternalBalance`, and `Balance` types.
pub mod balance;

/// Types for the genesis liquidity functionality.
pub mod genesis_liquidity;

/// Types for identifying networks and their properties.
pub mod network_id;

/// Types for identifying and working with validator sets.
pub mod validator_sets;

/// Types for the DEX.
pub mod dex;

/// Types for signaling.
pub mod signals;

/// Instruction types.
pub mod instructions;

/// Merkle trees.
pub mod merkle;

/// The type used to identify block numbers.
///
/// A block's number is its zero-indexed position on the list of blocks which form a blockchain.
/// For non-linear structures, this would presumably be the zero-indexed position within some
/// topological order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct BlockNumber(pub u64);
impl From<u64> for BlockNumber {
  fn from(number: u64) -> BlockNumber {
    BlockNumber(number)
  }
}

/// The type used to identify block hashes.
/*
  Across all networks, block hashes may not be 32 bytes. There may be a network which targets 256
  bits of security and accordingly has a 64-byte block hash. Serai only targets a 128-bit security
  level so this is fine for our use-case. If we do ever see a 64-byte block hash, we can simply
  hash it into a 32-byte hash or truncate it.
*/
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "non_canonical_scale_derivations", derive(scale::Encode, scale::Decode))]
#[cfg_attr(feature = "serde", derive(sp_core::serde::Serialize, sp_core::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "sp_core::serde"))]
pub struct BlockHash(pub [u8; 32]);
impl From<[u8; 32]> for BlockHash {
  fn from(hash: [u8; 32]) -> BlockHash {
    BlockHash(hash)
  }
}
impl From<sp_core::H256> for BlockHash {
  fn from(hash: sp_core::H256) -> BlockHash {
    BlockHash(hash.into())
  }
}

impl fmt::Display for BlockHash {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in self.0 {
      write!(f, "{byte:02x}")?;
    }
    Ok(())
  }
}

// These share encodings as 32-byte arrays
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::EncodeLike<sp_core::H256> for BlockHash {}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::EncodeLike<sp_core::H256> for &BlockHash {}

#[doc(hidden)]
pub mod prelude {
  pub use crate::{BlockNumber, BlockHash};
  pub use crate::constants::*;
  pub use crate::address::{SeraiAddress, ExternalAddress};
  pub use crate::coin::*;
  pub use crate::balance::*;
  pub use crate::network_id::*;
  pub use crate::validator_sets::*;
  pub use crate::instructions::*;
}

#[doc(hidden)]
#[cfg(feature = "non_canonical_scale_derivations")]
pub fn read_scale_as_borsh<T: borsh::BorshDeserialize, I: scale::Input>(
  input: &mut I,
) -> Result<T, scale::Error> {
  struct ScaleRead<'a, I: scale::Input>(&'a mut I, Option<scale::Error>);
  impl<I: scale::Input> borsh::io::Read for ScaleRead<'_, I> {
    fn read(&mut self, buf: &mut [u8]) -> borsh::io::Result<usize> {
      let remaining_len = self.0.remaining_len().map_err(|err| {
        self.1 = Some(err);
        #[allow(clippy::io_other_error)]
        borsh::io::Error::new(borsh::io::ErrorKind::Other, "")
      })?;
      // If we're still calling `read`, we try to read at least one more byte
      let to_read = buf.len().min(remaining_len.unwrap_or(1));
      // This may not be _allocated_ making this over-zealous, but it's the best we can do
      self.0.on_before_alloc_mem(to_read).map_err(|err| {
        self.1 = Some(err);
        #[allow(clippy::io_other_error)]
        borsh::io::Error::new(borsh::io::ErrorKind::Other, "")
      })?;
      self.0.read(&mut buf[.. to_read]).map_err(|err| {
        self.1 = Some(err);
        #[allow(clippy::io_other_error)]
        borsh::io::Error::new(borsh::io::ErrorKind::Other, "")
      })?;
      Ok(to_read)
    }
  }
  let mut input = ScaleRead(input, None);
  match T::deserialize_reader(&mut input) {
    Ok(res) => Ok(res),
    Err(_) => Err(input.1.unwrap()),
  }
}
