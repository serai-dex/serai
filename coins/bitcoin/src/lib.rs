#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#![doc = include_str!("../README.md")]

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
pub mod rpc;
