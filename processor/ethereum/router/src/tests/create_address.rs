use alloy_core::primitives::{hex, U256, Bytes, TxKind};
use alloy_sol_types::SolCall;

use alloy_consensus::TxLegacy;

use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_provider::Provider;

use revm::{primitives::SpecId, interpreter::gas::calculate_initial_tx_gas};

use crate::tests::Test;

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod abi {
  alloy_sol_macro::sol!("contracts/tests/CreateAddress.sol");
}

#[tokio::test]
async fn test_create_address() {
  let test = Test::new().await;

  let address = {
    const BYTECODE: &[u8] = {
      const BYTECODE_HEX: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/serai-processor-ethereum-router/tests/CreateAddress.bin"
      ));
      const BYTECODE: [u8; BYTECODE_HEX.len() / 2] =
        match hex::const_decode_to_array::<{ BYTECODE_HEX.len() / 2 }>(BYTECODE_HEX) {
          Ok(bytecode) => bytecode,
          Err(_) => panic!("CreateAddress.bin did not contain valid hex"),
        };
      &BYTECODE
    };

    let tx = TxLegacy {
      chain_id: None,
      nonce: 0,
      gas_price: 100_000_000_000u128,
      gas_limit: 1_100_000,
      to: TxKind::Create,
      value: U256::ZERO,
      input: Bytes::from_static(BYTECODE),
    };
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx).await;
    receipt.contract_address.unwrap()
  };

  // Check `createAddress` correctly encodes the nonce for every single meaningful bit pattern
  // The only meaningful patterns are < 0x80, == 0x80, and then each length greater > 0x80
  // The following covers all three
  let mut nonce = 1u64;
  let mut gas = None;
  while nonce.checked_add(nonce).is_some() {
    let input =
      (abi::CreateAddress::createAddressForSelfCall { nonce: U256::from(nonce) }).abi_encode();

    // Make sure the function works as expected
    let call =
      TransactionRequest::default().to(address).input(TransactionInput::new(input.clone().into()));
    assert_eq!(
      &test.provider.call(&call).await.unwrap().as_ref()[12 ..],
      address.create(nonce).as_slice(),
    );

    // Check the function is constant-gas
    let gas_used = test.provider.estimate_gas(&call).await.unwrap();
    let initial_gas = calculate_initial_tx_gas(SpecId::CANCUN, &input, false, &[], 0).initial_gas;
    let this_call = gas_used - initial_gas;
    if gas.is_none() {
      gas = Some(this_call);
    }
    assert_eq!(gas, Some(this_call));

    nonce <<= 1;
  }

  println!("createAddress gas: {}", gas.unwrap());
}
