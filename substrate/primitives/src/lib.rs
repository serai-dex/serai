#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

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

/// Types for genesis.
pub mod genesis;

/// Types for identifying networks and their properties.
pub mod network_id;

/// Types for identifying and working with validator sets.
pub mod validator_sets;

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
#[rustfmt::skip]
#[derive(scale::Encode, scale::Decode)] // This is safe as scale and borsh share an encoding here
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

// These share encodings as 32-byte arrays
impl scale::EncodeLike<sp_core::H256> for BlockHash {}
impl scale::EncodeLike<sp_core::H256> for &BlockHash {}
