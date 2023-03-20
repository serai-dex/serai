/// The bitcoin Rust library.
pub use bitcoin;

/// Cryptographic helpers.
pub mod crypto;
/// Wallet functionality to create transactions.
pub mod wallet;
/// A minimal asynchronous Bitcoin RPC client.
pub mod rpc;

#[cfg(test)]
mod tests;
