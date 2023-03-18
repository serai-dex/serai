/// The bitcoin Rust library.
pub use bitcoin;

/// Cryptographic helpers.
pub mod crypto;
/// BIP-340 Schnorr signature algorithm.
pub mod algorithm;
/// Wallet functionality to create transactions.
pub mod wallet;
/// A minimal asynchronous Bitcoin RPC client.
pub mod rpc;

#[cfg(test)]
mod tests;
