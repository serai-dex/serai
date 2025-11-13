#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(non_snake_case)]
#![cfg_attr(not(feature = "std"), no_std)]

mod public_key;
pub use public_key::PublicKey;
mod signature;
pub use signature::Signature;

#[cfg(test)]
mod tests;
