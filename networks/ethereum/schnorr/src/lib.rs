#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(non_snake_case)]

/// The initialization bytecode of the Schnorr library.
pub const INIT_BYTECODE: &str = include_str!("../artifacts/Schnorr.bin");

mod public_key;
pub use public_key::PublicKey;
mod signature;
pub use signature::Signature;

#[cfg(test)]
mod tests;
