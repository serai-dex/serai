#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::sync::Arc;

use alloy_core::primitives::{hex::FromHex, Address, U256, Bytes, TxKind};
use alloy_consensus::{Signed, TxLegacy};

use alloy_sol_types::SolCall;

use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_transport::{TransportErrorKind, RpcError};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod abi {
  alloy_sol_macro::sol!("contracts/Deployer.sol");
}

/// The Deployer contract for the Serai Router contract.
///
/// This Deployer has a deterministic address, letting it be immediately identified on any
/// compatible chain. It then supports retrieving the Router contract's address (which isn't
/// deterministic) using a single call.
#[derive(Clone, Debug)]
pub struct Deployer;
impl Deployer {
  /// Obtain the transaction to deploy this contract, already signed.
  ///
  /// The account this transaction is sent from (which is populated in `from`) must be sufficiently
  /// funded for this transaction to be submitted. This account has no known private key to anyone
  /// so ETH sent can be neither misappropriated nor returned.
  pub fn deployment_tx() -> Signed<TxLegacy> {
    pub const BYTECODE: &str =
      include_str!(concat!(env!("OUT_DIR"), "/serai-processor-ethereum-deployer/Deployer.bin"));
    let bytecode =
      Bytes::from_hex(BYTECODE).expect("compiled-in Deployer bytecode wasn't valid hex");

    let tx = TxLegacy {
      chain_id: None,
      nonce: 0,
      // 100 gwei
      gas_price: 100_000_000_000u128,
      // TODO: Use a more accurate gas limit
      gas_limit: 1_000_000u128,
      to: TxKind::Create,
      value: U256::ZERO,
      input: bytecode,
    };

    ethereum_primitives::deterministically_sign(&tx)
  }

  /// Obtain the deterministic address for this contract.
  pub(crate) fn address() -> Address {
    let deployer_deployer =
      Self::deployment_tx().recover_signer().expect("deployment_tx didn't have a valid signature");
    Address::create(&deployer_deployer, 0)
  }

  /// Construct a new view of the Deployer.
  pub async fn new(
    provider: Arc<RootProvider<SimpleRequest>>,
  ) -> Result<Option<Self>, RpcError<TransportErrorKind>> {
    let address = Self::address();
    let code = provider.get_code_at(address).await?;
    // Contract has yet to be deployed
    if code.is_empty() {
      return Ok(None);
    }
    Ok(Some(Self))
  }

  /// Find the deployment of a contract.
  pub async fn find_deployment(
    &self,
    provider: Arc<RootProvider<SimpleRequest>>,
    init_code_hash: [u8; 32],
  ) -> Result<Option<abi::Deployer::Deployment>, RpcError<TransportErrorKind>> {
    let call = TransactionRequest::default().to(Self::address()).input(TransactionInput::new(
      abi::Deployer::deploymentsCall::new((init_code_hash.into(),)).abi_encode().into(),
    ));
    let bytes = provider.call(&call).await?;
    let deployment = abi::Deployer::deploymentsCall::abi_decode_returns(&bytes, true)
      .map_err(|e| {
        TransportErrorKind::Custom(
          format!("node returned a non-Deployment for function returning Deployment: {e:?}").into(),
        )
      })?
      ._0;

    if deployment.created_contract == [0; 20] {
      return Ok(None);
    }
    Ok(Some(deployment))
  }
}
