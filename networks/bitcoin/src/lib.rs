#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

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
#[cfg(feature = "rpc")]
pub mod rpc;

#[cfg(test)]
mod tests;
