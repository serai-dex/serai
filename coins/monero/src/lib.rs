#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use monero_io as io;
pub use monero_generators as generators;
pub use monero_primitives as primitives;

mod merkle;

/// Ring Signature structs and functionality.
pub mod ring_signatures;

/// RingCT structs and functionality.
pub mod ringct;

/// Transaction structs and functionality.
pub mod transaction;
/// Block structs and functionality.
pub mod block;

#[cfg(test)]
mod tests;

/// The minimum amount of blocks an output is locked for.
///
/// If Monero suffered a re-organization, any transactions which selected decoys belonging to
/// recent blocks would become invalidated. Accordingly, transactions must use decoys which are
/// presumed to not be invalidated in the future. If wallets only selected n-block-old outputs as
/// decoys, then any ring member within the past n blocks would have to be the real spend.
/// Preventing this at the consensus layer ensures privacy and integrity.
pub const DEFAULT_LOCK_WINDOW: usize = 10;

/// The minimum amount of blocks a coinbase output is locked for.
pub const COINBASE_LOCK_WINDOW: usize = 60;

/// Monero's block time target, in seconds.
pub const BLOCK_TIME: usize = 120;
