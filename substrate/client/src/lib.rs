#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

/// The client for the Serai network itself.
#[cfg(feature = "serai")]
pub use serai_client_serai as serai;

/// The client for the Bitcoin integration.
#[cfg(feature = "bitcoin")]
pub use serai_client_bitcoin as bitcoin;
/// The client for the Ethereum integration.
#[cfg(feature = "ethereum")]
pub use serai_client_ethereum as ethereum;
/// The client for the Monero integration.
#[cfg(feature = "monero")]
pub use serai_client_monero as monero;
