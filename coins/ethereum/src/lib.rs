use thiserror::Error;

pub mod alloy {
  pub use alloy_core::primitives;
  pub use alloy_core as core;
  pub use alloy_sol_types as sol_types;

  pub use alloy_consensus as consensus;
  pub use alloy_network as network;
  pub use alloy_rpc_types_eth as rpc_types;
  pub use alloy_simple_request_transport as simple_request_transport;
  pub use alloy_rpc_client as rpc_client;
  pub use alloy_provider as provider;
}

pub mod crypto;

pub(crate) mod abi;

pub mod erc20;
pub mod deployer;
pub mod router;

pub mod machine;

#[cfg(any(test, feature = "tests"))]
pub mod tests;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum Error {
  #[error("failed to verify Schnorr signature")]
  InvalidSignature,
  #[error("couldn't make call/send TX")]
  ConnectionError,
}
