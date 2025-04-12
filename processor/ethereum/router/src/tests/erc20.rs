use alloy_core::primitives::{hex, Address, U256, Bytes, TxKind};
use alloy_sol_types::{SolValue, SolCall};

use alloy_consensus::TxLegacy;

use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_provider::Provider;

use crate::tests::Test;

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod abi {
  alloy_sol_macro::sol!("contracts/tests/ERC20.sol");
}

pub struct Erc20(Address);
impl Erc20 {
  pub(crate) async fn deploy(test: &Test) -> Self {
    const BYTECODE: &[u8] = {
      const BYTECODE_HEX: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/serai-processor-ethereum-router/tests/TestERC20.bin"
      ));
      const BYTECODE: [u8; BYTECODE_HEX.len() / 2] =
        match hex::const_decode_to_array::<{ BYTECODE_HEX.len() / 2 }>(BYTECODE_HEX) {
          Ok(bytecode) => bytecode,
          Err(_) => panic!("TestERC20.bin did not contain valid hex"),
        };
      &BYTECODE
    };

    let tx = TxLegacy {
      chain_id: None,
      nonce: 0,
      gas_price: 100_000_000_000u128,
      gas_limit: 1_000_000,
      to: TxKind::Create,
      value: U256::ZERO,
      input: Bytes::from_static(BYTECODE),
    };
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx).await;
    Self(receipt.contract_address.unwrap())
  }

  pub(crate) fn address(&self) -> Address {
    self.0
  }

  pub(crate) async fn approve(&self, test: &Test, owner: Address, spender: Address, amount: U256) {
    let tx = TxLegacy {
      chain_id: None,
      nonce: 0,
      gas_price: 100_000_000_000u128,
      gas_limit: 1_000_000,
      to: self.0.into(),
      value: U256::ZERO,
      input: abi::TestERC20::magicApproveCall::new((owner, spender, amount)).abi_encode().into(),
    };
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx).await;
    assert!(receipt.status());
  }

  pub(crate) async fn mint(&self, test: &Test, account: Address, amount: U256) {
    let tx = TxLegacy {
      chain_id: None,
      nonce: 0,
      gas_price: 100_000_000_000u128,
      gas_limit: 1_000_000,
      to: self.0.into(),
      value: U256::ZERO,
      input: abi::TestERC20::mintCall::new((account, amount)).abi_encode().into(),
    };
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx).await;
    assert!(receipt.status());
  }

  pub(crate) async fn balance_of(&self, test: &Test, account: Address) -> U256 {
    let call = TransactionRequest::default().to(self.0).input(TransactionInput::new(
      abi::TestERC20::balanceOfCall::new((account,)).abi_encode().into(),
    ));
    U256::abi_decode(&test.provider.call(call).await.unwrap()).unwrap()
  }

  pub(crate) async fn router_approval(&self, test: &Test, account: Address) -> U256 {
    let call = TransactionRequest::default().to(self.0).input(TransactionInput::new(
      abi::TestERC20::allowanceCall::new((test.router.address(), account)).abi_encode().into(),
    ));
    U256::abi_decode(&test.provider.call(call).await.unwrap()).unwrap()
  }
}
