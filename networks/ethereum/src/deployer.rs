use std::sync::Arc;

use alloy_core::primitives::{hex::FromHex, Address, B256, U256, Bytes, TxKind};
use alloy_consensus::{Signed, TxLegacy};

use alloy_sol_types::{SolCall, SolEvent};

use alloy_rpc_types_eth::{BlockNumberOrTag, Filter};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use crate::{
  Error,
  crypto::{self, keccak256, PublicKey},
  router::Router,
};
pub use crate::abi::deployer as abi;

/// The Deployer contract for the Router contract.
///
/// This Deployer has a deterministic address, letting it be immediately identified on any
/// compatible chain. It then supports retrieving the Router contract's address (which isn't
/// deterministic) using a single log query.
#[derive(Clone, Debug)]
pub struct Deployer;
impl Deployer {
  /// Obtain the transaction to deploy this contract, already signed.
  ///
  /// The account this transaction is sent from (which is populated in `from`) must be sufficiently
  /// funded for this transaction to be submitted. This account has no known private key to anyone,
  /// so ETH sent can be neither misappropriated nor returned.
  pub fn deployment_tx() -> Signed<TxLegacy> {
    let bytecode = include_str!("../artifacts/Deployer.bin");
    let bytecode =
      Bytes::from_hex(bytecode).expect("compiled-in Deployer bytecode wasn't valid hex");

    let tx = TxLegacy {
      chain_id: None,
      nonce: 0,
      gas_price: 100_000_000_000u128,
      // TODO: Use a more accurate gas limit
      gas_limit: 1_000_000u128,
      to: TxKind::Create,
      value: U256::ZERO,
      input: bytecode,
    };

    crypto::deterministically_sign(&tx)
  }

  /// Obtain the deterministic address for this contract.
  pub fn address() -> [u8; 20] {
    let deployer_deployer =
      Self::deployment_tx().recover_signer().expect("deployment_tx didn't have a valid signature");
    **Address::create(&deployer_deployer, 0)
  }

  /// Construct a new view of the `Deployer`.
  pub async fn new(provider: Arc<RootProvider<SimpleRequest>>) -> Result<Option<Self>, Error> {
    let address = Self::address();
    let code = provider.get_code_at(address.into()).await.map_err(|_| Error::ConnectionError)?;
    // Contract has yet to be deployed
    if code.is_empty() {
      return Ok(None);
    }
    Ok(Some(Self))
  }

  /// Yield the `ContractCall` necessary to deploy the Router.
  pub fn deploy_router(&self, key: &PublicKey) -> TxLegacy {
    TxLegacy {
      to: TxKind::Call(Self::address().into()),
      input: abi::deployCall::new((Router::init_code(key).into(),)).abi_encode().into(),
      gas_limit: 1_000_000,
      ..Default::default()
    }
  }

  /// Find the first Router deployed with the specified key as its first key.
  ///
  /// This is the Router Serai will use, and is the only way to construct a `Router`.
  pub async fn find_router(
    &self,
    provider: Arc<RootProvider<SimpleRequest>>,
    key: &PublicKey,
  ) -> Result<Option<Router>, Error> {
    let init_code = Router::init_code(key);
    let init_code_hash = keccak256(&init_code);

    #[cfg(not(test))]
    let to_block = BlockNumberOrTag::Finalized;
    #[cfg(test)]
    let to_block = BlockNumberOrTag::Latest;

    // Find the first log using this init code (where the init code is binding to the key)
    // TODO: Make an abstraction for event filtering (de-duplicating common code)
    let filter =
      Filter::new().from_block(0).to_block(to_block).address(Address::from(Self::address()));
    let filter = filter.event_signature(abi::Deployment::SIGNATURE_HASH);
    let filter = filter.topic1(B256::from(init_code_hash));
    let logs = provider.get_logs(&filter).await.map_err(|_| Error::ConnectionError)?;

    let Some(first_log) = logs.first() else { return Ok(None) };
    let router = first_log
      .log_decode::<abi::Deployment>()
      .map_err(|_| Error::ConnectionError)?
      .inner
      .data
      .created;

    Ok(Some(Router::new(provider, router)))
  }
}
