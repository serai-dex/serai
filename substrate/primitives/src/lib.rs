#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;
extern crate alloc;

use zeroize::Zeroize;
use ::borsh::{BorshSerialize, BorshDeserialize};

/// Utilities to implement and bind Borsh into Substrate's expectations.
#[doc(hidden)]
pub mod sp_borsh;
pub use sp_borsh::BitVec;
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
pub struct BlockHash(pub [u8; 32]);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(BlockHash);

#[cfg(feature = "scale")]
impl scale::EncodeLike<sp_core::H256> for BlockHash {}
#[cfg(feature = "scale")]
impl scale::EncodeLike<sp_core::H256> for &BlockHash {}
#[cfg(feature = "scale")]
impl scale::EncodeLike<BlockHash> for sp_core::H256 {}
#[cfg(feature = "scale")]
impl scale::EncodeLike<BlockHash> for &sp_core::H256 {}

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
