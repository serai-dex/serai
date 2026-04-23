#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use std::sync::Arc;

use alloy_core::primitives::{hex, Address, U256, Bytes, TxKind};
use alloy_consensus::{Signed, TxLegacy};

use alloy_sol_types::SolCall as _;

use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_transport::{TransportErrorKind, RpcError};
use alloy_provider::{Provider as _, RootProvider};

#[cfg(test)]
mod tests;

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod abi {
  alloy_sol_macro::sol!("contracts/Deployer.sol");
}

const INITCODE: &[u8] = {
  const INITCODE_HEX: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/serai-processor-ethereum-deployer/Deployer.bin"));
  const INITCODE: [u8; INITCODE_HEX.len() / 2] =
    match hex::const_decode_to_array::<{ INITCODE_HEX.len() / 2 }>(INITCODE_HEX) {
      Ok(initcode) => initcode,
      Err(_) => panic!("Deployer.bin did not contain valid hex"),
    };
  &INITCODE
};

/// The Deployer contract for the Serai Router contract.
///
/// This Deployer has a deterministic address, letting it be immediately identified on any instance
/// of the EVM. It then supports retrieving the deployed contracts addresses (which aren't
/// deterministic) using a single call.
#[derive(Clone, Debug)]
pub struct Deployer(Arc<RootProvider>);
impl Deployer {
  /// Obtain the transaction to deploy this contract, already signed.
  ///
  /// The account this transaction is sent from (which is populated in `from`) must be sufficiently
  /// funded for this transaction to be submitted. This account has no known private key to anyone
  /// so ETH sent can be neither misappropriated nor returned.
  pub fn deployment_tx() -> Signed<TxLegacy> {
    let initcode = Bytes::from_static(INITCODE);

    // Legacy transactions are used to ensure the widest possible degree of support across EVMs
    let tx = TxLegacy {
      chain_id: None,
      nonce: 0,
      /*
        This needs to use a fixed gas price to achieve a deterministic address. The gas price is
        fixed to 100 gwei, which should be generous, in order to make this unlikely to get stuck.
        While potentially expensive, this only has to occur per chain this is deployed on.

        If this is too low of a gas price, private mempools can be used, with other transactions in
        the bundle raising the gas price to acceptable levels. While this strategy could be
        entirely relied upon, allowing the gas price paid to reflect the network's actual gas
        price, that wouldn't work for EVM networks without private mempools.

        That leaves this as failing only if it violates a protocol constant, or if the gas price is
        too low on a network without private mempools to publish via. In that case, this code
        should to be forked to accept an enum of which network the deployment is for (with the gas
        price derivative of that, as common as possible across networks to minimize the amount of
        addresses representing the Deployer).
      */
      gas_price: 100_000_000_000u128,
      /*
        This is twice the cost of deployment as of Ethereum's Osaka upgrade. The wide margin is to
        increase the likelihood of surviving changes to the cost of contract deployment (notably
        the gas cost of calldata). While wasteful, this only has to be done once per chain and is
        accepted accordingly.

        If this is ever unacceptable, the parameterization suggested in case the `gas_price` is
        unacceptable should be implemented.
      */
      gas_limit: 300_698,
      to: TxKind::Create,
      value: U256::ZERO,
      input: initcode,
    };

    ethereum_primitives::deterministically_sign(tx)
  }

  /// Obtain the deterministic address for this contract.
  pub fn address() -> Address {
    let deployer_deployer =
      Self::deployment_tx().recover_signer().expect("deployment_tx didn't have a valid signature");
    Address::create(&deployer_deployer, 0)
  }

  /// Obtain the unsigned transaction to deploy a contract.
  ///
  /// This will not have its `nonce`, `gas_price`, nor `gas_limit` filled out.
  pub fn deploy_tx(init_code: Vec<u8>) -> TxLegacy {
    TxLegacy {
      chain_id: None,
      nonce: 0,
      gas_price: 0,
      gas_limit: 0,
      to: TxKind::Call(Self::address()),
      value: U256::ZERO,
      input: abi::Deployer::deployCall::new((init_code.into(),)).abi_encode().into(),
    }
  }

  /// Construct a new view of the Deployer.
  ///
  /// This will return `None` if the Deployer has yet to be deployed on-chain.
  pub async fn new(
    provider: Arc<RootProvider>,
  ) -> Result<Option<Self>, RpcError<TransportErrorKind>> {
    let address = Self::address();
    let code = provider.get_code_at(address).await?;
    // Contract has yet to be deployed
    if code.is_empty() {
      return Ok(None);
    }
    Ok(Some(Self(provider)))
  }

  /// Find the deployment of a contract.
  pub async fn find_deployment(
    &self,
    init_code_hash: [u8; 32],
  ) -> Result<Option<Address>, RpcError<TransportErrorKind>> {
    let call = TransactionRequest::default().to(Self::address()).input(TransactionInput::new(
      abi::Deployer::deploymentsCall::new((init_code_hash.into(),)).abi_encode().into(),
    ));
    let bytes = self.0.call(call).await?;
    let deployment = abi::Deployer::deploymentsCall::abi_decode_returns(&bytes).map_err(|e| {
      TransportErrorKind::Custom(
        format!("node returned a non-address for function returning address: {e:?}").into(),
      )
    })?;

    if deployment == Address::ZERO {
      return Ok(None);
    }
    Ok(Some(deployment))
  }
}
