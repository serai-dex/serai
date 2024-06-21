#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
// #![deny(missing_docs)] // TODO
#![cfg_attr(not(feature = "std"), no_std)]

pub use monero_io as io;
pub use monero_generators as generators;
pub use monero_primitives as primitives;

mod merkle;

/// Ring Signature structs and functionality.
pub mod ring_signatures;

/// RingCT structs and functionality.
pub mod ringct;

/// Transaction structs.
pub mod transaction;
/// Block structs.
pub mod block;

pub const DEFAULT_LOCK_WINDOW: usize = 10;
pub const COINBASE_LOCK_WINDOW: usize = 60;
pub const BLOCK_TIME: usize = 120;
