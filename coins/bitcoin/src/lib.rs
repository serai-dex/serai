#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// The bitcoin Rust library.
pub use bitcoin;

/// Cryptographic helpers.
#[cfg(feature = "hazmat")]
pub mod crypto;
#[cfg(not(feature = "hazmat"))]
pub(crate) mod crypto;

/// Wallet functionality to create transactions.
pub mod wallet;
/// A minimal asynchronous Bitcoin RPC client.
#[cfg(feature = "std")]
pub mod rpc;

#[cfg(test)]
mod tests;
