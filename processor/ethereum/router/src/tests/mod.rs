use std::sync::Arc;

use rand_core::{RngCore, OsRng};

use group::ff::Field;
use k256::{Scalar, ProjectivePoint};

use alloy_core::primitives::{Address, U256};
use alloy_sol_types::{SolValue, SolCall, SolEvent};

use alloy_consensus::{TxLegacy, Signed};

use alloy_rpc_types_eth::{BlockNumberOrTag, TransactionInput, TransactionRequest};
use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{
  Provider, RootProvider,
  ext::{DebugApi, TraceApi},
};

use alloy_node_bindings::{Anvil, AnvilInstance};

use serai_client_ethereum::{ContractDeployment, Address as SeraiEthereumAddress};

use ethereum_schnorr::{PublicKey, Signature};
use ethereum_deployer::Deployer;

use crate::{
  _irouter_abi::IRouterWithoutCollisions::{
    self as IRouter, IRouterWithoutCollisionsErrors as IRouterErrors,
  },
  Coin, OutInstructions, Router, Executed, Escape,
};

mod constants;

mod erc20;
use erc20::Erc20;

mod create_address;
mod in_instruction;
mod escape_hatch;

pub(crate) fn test_key() -> (Scalar, PublicKey) {
  loop {
    let key = Scalar::random(&mut OsRng);
    let point = ProjectivePoint::GENERATOR * key;
    if let Some(public_key) = PublicKey::new(point) {
      return (key, public_key);
    }
  }
}

fn sign(key: (Scalar, PublicKey), msg: &[u8]) -> Signature {
  let nonce = Scalar::random(&mut OsRng);
  let c = Signature::challenge(ProjectivePoint::GENERATOR * nonce, &key.1, msg);
  let s = nonce + (c * key.0);
  Signature::new(c, s).unwrap()
}

/// Calculate the gas used by a transaction if none of its calldata's bytes were zero
struct CalldataAgnosticGas;
impl CalldataAgnosticGas {
  #[must_use]
  fn calculate(input: &[u8], mut constant_zero_bytes: usize, gas_used: u64) -> u64 {
    use revm::{primitives::hardfork::SpecId, interpreter::gas::calculate_initial_tx_gas};

    let mut without_variable_zero_bytes = Vec::with_capacity(input.len());
    for byte in input {
      if (constant_zero_bytes > 0) && (*byte == 0) {
        constant_zero_bytes -= 1;
        without_variable_zero_bytes.push(0);
      } else {
        // If this is a variably zero byte, or a non-zero byte, push a non-zero byte
        without_variable_zero_bytes.push(0xff);
      }
    }
    gas_used +
      (calculate_initial_tx_gas(SpecId::CANCUN, &without_variable_zero_bytes, false, 0, 0, 0)
        .initial_gas -
        calculate_initial_tx_gas(SpecId::CANCUN, input, false, 0, 0, 0).initial_gas)
  }
}

struct RouterState {
  next_key: Option<(Scalar, PublicKey)>,
  key: Option<(Scalar, PublicKey)>,
  next_nonce: u64,
  escaped_to: Option<Address>,
}

struct Test {
  #[expect(unused)]
  anvil: AnvilInstance,
  provider: Arc<RootProvider>,
  chain_id: U256,
  router: Router,
  state: RouterState,
}

impl Test {
  async fn verify_state(&self) {
    assert_eq!(
      self.router.next_key(BlockNumberOrTag::Latest.into()).await.unwrap(),
      self.state.next_key.map(|key| key.1)
    );
    assert_eq!(
      self.router.key(BlockNumberOrTag::Latest.into()).await.unwrap(),
      self.state.key.map(|key| key.1)
    );
    assert_eq!(
      self.router.next_nonce(BlockNumberOrTag::Latest.into()).await.unwrap(),
      self.state.next_nonce
    );
    assert_eq!(
      self.router.escaped_to(BlockNumberOrTag::Latest.into()).await.unwrap(),
      self.state.escaped_to,
    );
  }

  async fn new() -> Self {
    // The following is explicitly only evaluated against the cancun network upgrade at this time
    let anvil = Anvil::new()
      .arg("--hardfork")
      .arg("cancun")
      .arg("--tracing")
      .arg("--no-request-size-limit")
      .arg("--disable-block-gas-limit")
      .spawn();

    let provider = Arc::new(RootProvider::new(
      ClientBuilder::default().transport(SimpleRequest::new(anvil.endpoint()).unwrap(), true),
    ));
    let chain_id = U256::from(provider.get_chain_id().await.unwrap());

    let (private_key, public_key) = test_key();
    assert!(Router::new(provider.clone(), &public_key).await.unwrap().is_none());

    // Deploy the Deployer
    let receipt = ethereum_test_primitives::publish_tx(&provider, Deployer::deployment_tx()).await;
    assert!(receipt.status());

    let mut tx = Router::deployment_tx(&public_key);
    tx.gas_limit = 1_100_000;
    tx.gas_price = 100_000_000_000;
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&provider, tx).await;
    assert!(receipt.status());

    let router = Router::new(provider.clone(), &public_key).await.unwrap().unwrap();
    let state = RouterState {
      next_key: Some((private_key, public_key)),
      key: None,
      // Nonce 0 should've been consumed by setting the next key to the key initialized with
      next_nonce: 1,
      escaped_to: None,
    };

    // Confirm nonce 0 was used as such
    {
      let block = receipt.block_number.unwrap();
      let executed = router.executed(block ..= block).await.unwrap();
      assert_eq!(executed.len(), 1);
      assert_eq!(executed[0], Executed::NextSeraiKeySet { nonce: 0, key: public_key.eth_repr() });
    }

    let res = Test { anvil, provider, chain_id, router, state };
    res.verify_state().await;
    res
  }

  async fn call_and_decode_err(&self, tx: TxLegacy) -> IRouterErrors {
    let call = TransactionRequest::default()
      .to(self.router.address())
      .input(TransactionInput::new(tx.input));
    let call_err = self.provider.call(call).await.unwrap_err();
    call_err.as_error_resp().unwrap().as_decoded_interface_error::<IRouterErrors>().unwrap()
  }

  fn confirm_next_serai_key_tx(&self) -> TxLegacy {
    let msg = Router::confirm_next_serai_key_message(
      self.chain_id,
      self.router.address(),
      self.state.next_nonce,
    );
    let sig = sign(self.state.next_key.unwrap(), &msg);

    self.router.confirm_next_serai_key(&sig)
  }

  async fn confirm_next_serai_key(&mut self) {
    let mut tx = self.confirm_next_serai_key_tx();
    tx.gas_limit = Router::CONFIRM_NEXT_SERAI_KEY_GAS + 5_000;
    tx.gas_price = 100_000_000_000;
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&self.provider, tx.clone()).await;
    assert!(receipt.status());
    // Only check the gas is equal when writing to a previously unallocated storage slot, as this
    // is the highest possible gas cost and what the constant is derived from
    if self.state.key.is_none() {
      assert_eq!(
        CalldataAgnosticGas::calculate(tx.tx().input.as_ref(), 0, receipt.gas_used),
        Router::CONFIRM_NEXT_SERAI_KEY_GAS,
      );
    } else {
      assert!(
        CalldataAgnosticGas::calculate(tx.tx().input.as_ref(), 0, receipt.gas_used) <
          Router::CONFIRM_NEXT_SERAI_KEY_GAS
      );
    }

    {
      let block = receipt.block_number.unwrap();
      let executed = self.router.executed(block ..= block).await.unwrap();
      assert_eq!(executed.len(), 1);
      assert_eq!(
        executed[0],
        Executed::SeraiKeyUpdated {
          nonce: self.state.next_nonce,
          key: self.state.next_key.unwrap().1.eth_repr()
        }
      );
    }

    self.state.next_nonce += 1;
    self.state.key = self.state.next_key;
    self.state.next_key = None;
    self.verify_state().await;
  }

  fn update_serai_key_tx(&self) -> ((Scalar, PublicKey), TxLegacy) {
    let next_key = test_key();

    let msg = Router::update_serai_key_message(
      self.chain_id,
      self.router.address(),
      self.state.next_nonce,
      &next_key.1,
    );
    let sig = sign(self.state.key.unwrap(), &msg);

    (next_key, self.router.update_serai_key(&next_key.1, &sig))
  }

  async fn update_serai_key(&mut self) {
    let (next_key, mut tx) = self.update_serai_key_tx();
    tx.gas_limit = Router::UPDATE_SERAI_KEY_GAS + 5_000;
    tx.gas_price = 100_000_000_000;
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&self.provider, tx.clone()).await;
    assert!(receipt.status());
    if self.state.next_key.is_none() {
      assert_eq!(
        CalldataAgnosticGas::calculate(tx.tx().input.as_ref(), 0, receipt.gas_used),
        Router::UPDATE_SERAI_KEY_GAS,
      );
    } else {
      assert!(
        CalldataAgnosticGas::calculate(tx.tx().input.as_ref(), 0, receipt.gas_used) <
          Router::UPDATE_SERAI_KEY_GAS
      );
    }

    {
      let block = receipt.block_number.unwrap();
      let executed = self.router.executed(block ..= block).await.unwrap();
      assert_eq!(executed.len(), 1);
      assert_eq!(
        executed[0],
        Executed::NextSeraiKeySet { nonce: self.state.next_nonce, key: next_key.1.eth_repr() }
      );
    }

    self.state.next_nonce += 1;
    self.state.next_key = Some(next_key);
    self.verify_state().await;
  }

  fn execute_tx(
    &self,
    coin: Coin,
    fee: U256,
    out_instructions: OutInstructions,
  ) -> ([u8; 32], TxLegacy) {
    let msg = Router::execute_message(
      self.chain_id,
      self.router.address(),
      self.state.next_nonce,
      coin,
      fee,
      out_instructions.clone(),
    );
    let msg_hash = ethereum_primitives::keccak256(&msg);
    let sig = loop {
      let sig = sign(self.state.key.unwrap(), &msg);
      // Standardize the zero bytes in the signature for calldata gas reasons
      let has_zero_byte = sig.to_bytes().iter().filter(|b| **b == 0).count() != 0;
      if has_zero_byte {
        continue;
      }
      break sig;
    };

    let tx = self.router.execute(coin, fee, out_instructions, &sig);
    (msg_hash, tx)
  }

  async fn execute(
    &mut self,
    coin: Coin,
    fee: U256,
    out_instructions: OutInstructions,
    results: Vec<bool>,
  ) -> (Signed<TxLegacy>, u64) {
    let (message_hash, mut tx) = self.execute_tx(coin, fee, out_instructions);
    tx.gas_limit = 100_000_000;
    tx.gas_price = 100_000_000_000;
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&self.provider, tx.clone()).await;
    assert!(receipt.status());

    // We don't check the gas for `execute` here, instead at the call-sites where we have
    // beneficial  context

    {
      let block = receipt.block_number.unwrap();
      let executed = self.router.executed(block ..= block).await.unwrap();
      assert_eq!(executed.len(), 1);
      assert_eq!(
        executed[0],
        Executed::Batch { nonce: self.state.next_nonce, message_hash, results }
      );
    }

    self.state.next_nonce += 1;
    self.verify_state().await;

    (tx.clone(), receipt.gas_used)
  }

  async fn gas_unused_by_calls(&self, tx: &Signed<TxLegacy>) -> u64 {
    let mut unused_gas = 0;

    // Handle the difference between the gas limits and gas used values
    let traces = self.provider.trace_transaction(*tx.hash()).await.unwrap();
    // Skip the initial call to the Router and the call to ecrecover
    let mut traces = traces.iter().skip(2);
    while let Some(trace) = traces.next() {
      let trace = &trace.trace;
      // We're tracing the Router's immediate actions, and it doesn't immediately call CREATE
      // It only makes a call to itself which calls CREATE
      let gas_provided = trace.action.as_call().as_ref().unwrap().gas;
      let gas_spent = trace.result.as_ref().unwrap().gas_used();
      unused_gas += gas_provided - gas_spent;

      let mut subtraces = trace.subtraces;
      while subtraces != 0 {
        // Skip the subtraces (and their subtraces) for this call (such as CREATE)
        subtraces += traces.next().unwrap().trace.subtraces;
        subtraces -= 1;
      }
    }

    // Also handle any refunds
    {
      let trace =
        self.provider.debug_trace_transaction(*tx.hash(), Default::default()).await.unwrap();
      let refund =
        trace.try_into_default_frame().unwrap().struct_logs.last().unwrap().refund_counter;
      // This isn't capped to 1/5th of the TX's gas usage yet that's fine as none of our tests are
      // so refund intensive
      unused_gas += refund.unwrap_or(0);
    }

    unused_gas
  }
}

#[tokio::test]
async fn test_constructor() {
  // `Test::new` internalizes all checks on initial state
  Test::new().await;
}

#[tokio::test]
async fn test_confirm_next_serai_key() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;
}

#[tokio::test]
async fn test_no_serai_key() {
  // Before we confirm a key, any operations requiring a signature shouldn't work
  {
    let mut test = Test::new().await;

    // Corrupt the test's state so we can obtain signed TXs
    test.state.key = Some(test_key());

    assert!(matches!(
      test.call_and_decode_err(test.update_serai_key_tx().1).await,
      IRouterErrors::SeraiKeyWasNone(IRouter::SeraiKeyWasNone {})
    ));
    assert!(matches!(
      test
        .call_and_decode_err(test.execute_tx(Coin::Ether, U256::from(0), [].as_slice().into()).1)
        .await,
      IRouterErrors::SeraiKeyWasNone(IRouter::SeraiKeyWasNone {})
    ));
    assert!(matches!(
      test.call_and_decode_err(test.escape_hatch_tx(Address::ZERO)).await,
      IRouterErrors::SeraiKeyWasNone(IRouter::SeraiKeyWasNone {})
    ));
  }

  // And if there's no key to confirm, any operations requiring a signature shouldn't work
  {
    let mut test = Test::new().await;
    test.confirm_next_serai_key().await;
    test.state.next_key = Some(test_key());
    assert!(matches!(
      test.call_and_decode_err(test.confirm_next_serai_key_tx()).await,
      IRouterErrors::SeraiKeyWasNone(IRouter::SeraiKeyWasNone {})
    ));
  }
}

#[tokio::test]
async fn test_invalid_signature() {
  let mut test = Test::new().await;

  {
    let mut tx = test.confirm_next_serai_key_tx();
    // Cut it down to the function signature
    tx.input = tx.input.as_ref()[.. 4].to_vec().into();
    assert!(matches!(
      test.call_and_decode_err(tx).await,
      IRouterErrors::InvalidSignature(IRouter::InvalidSignature {})
    ));
  }

  {
    let mut tx = test.confirm_next_serai_key_tx();
    // Mutate the signature
    let mut input = Vec::<u8>::from(tx.input);
    *input.last_mut().unwrap() = input.last().unwrap().wrapping_add(1);
    tx.input = input.into();
    assert!(matches!(
      test.call_and_decode_err(tx).await,
      IRouterErrors::InvalidSignature(IRouter::InvalidSignature {})
    ));
  }

  test.confirm_next_serai_key().await;

  {
    let mut tx = test.update_serai_key_tx().1;
    // Mutate the message
    let mut input = Vec::<u8>::from(tx.input);
    *input.last_mut().unwrap() = input.last().unwrap().wrapping_add(1);
    tx.input = input.into();
    assert!(matches!(
      test.call_and_decode_err(tx).await,
      IRouterErrors::InvalidSignature(IRouter::InvalidSignature {})
    ));
  }
}

#[tokio::test]
async fn test_update_serai_key() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;
  test.update_serai_key().await;

  // We should be able to update while an update is pending as well (in case the new key never
  // confirms)
  test.update_serai_key().await;

  // But we shouldn't be able to update the key to None
  {
    let router_address_u256: U256 = test.router.address().into_word().into();
    let s: U256 = (router_address_u256 << 96) | U256::from(test.state.next_nonce);
    let msg = crate::abi::updateSeraiKeyCall::new((
      crate::abi::Signature { c: test.chain_id.into(), s: s.into() },
      [0; 32].into(),
    ))
    .abi_encode();
    let sig = sign(test.state.key.unwrap(), &msg);

    assert!(matches!(
      test
        .call_and_decode_err(TxLegacy {
          input: crate::abi::updateSeraiKeyCall::new((
            crate::abi::Signature::from(&sig),
            [0; 32].into(),
          ))
          .abi_encode()
          .into(),
          ..Default::default()
        })
        .await,
      IRouterErrors::InvalidSeraiKey(IRouter::InvalidSeraiKey {})
    ));
  }

  // Once we update to a new key, we should, of course, be able to continue to rotate keys
  test.confirm_next_serai_key().await;
}

#[tokio::test]
async fn test_execute_arbitrary_code() {
  let test = Test::new().await;

  assert!(matches!(
    test
      .call_and_decode_err(TxLegacy {
        chain_id: None,
        nonce: 0,
        gas_price: 100_000_000_000,
        gas_limit: 1_000_000,
        to: test.router.address().into(),
        value: U256::ZERO,
        input: crate::abi::executeArbitraryCodeCall::new((vec![].into(),)).abi_encode().into(),
      })
      .await,
    IRouterErrors::CodeNotBySelf(IRouter::CodeNotBySelf {})
  ));
}

// Code which returns true
#[rustfmt::skip]
fn return_true_code() -> Vec<u8> {
  vec![
    0x60, // push 1 byte                    | 3 gas
    0x01, // the value 1
    0x5f, // push 0                         | 2 gas
    0x52, // mstore to offset 0 the value 1 | 3 gas
    0x60, // push 1 byte                    | 3 gas
    0x20, // the value 32
    0x5f, // push 0                         | 2 gas
    0xf3, // return from offset 0 1 word    | 0 gas
    // 13 gas for the execution plus a single word of memory for 16 gas total
  ]
}

#[tokio::test]
async fn test_empty_execute() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  {
    let (gas, fee) =
      test.router.execute_gas_and_fee(Coin::Ether, U256::from(1), &[].as_slice().into());

    let () = test
      .provider
      .raw_request("anvil_setBalance".into(), (test.router.address(), fee))
      .await
      .unwrap();

    let (tx, gas_used) = test.execute(Coin::Ether, fee, [].as_slice().into(), vec![]).await;
    // We don't use the call gas stipend here
    const UNUSED_GAS: u64 = revm::interpreter::gas::CALL_STIPEND;
    assert_eq!(gas_used + UNUSED_GAS, gas);

    assert_eq!(test.provider.get_balance(test.router.address()).await.unwrap(), U256::from(0));
    let minted_to_sender = u128::from(tx.tx().gas_limit) * tx.tx().gas_price;
    let spent_by_sender = u128::from(gas_used) * tx.tx().gas_price;
    assert_eq!(
      test.provider.get_balance(tx.recover_signer().unwrap()).await.unwrap() -
        U256::from(minted_to_sender - spent_by_sender),
      U256::from(fee)
    );
  }

  {
    let token = Address::from([0xff; 20]);
    {
      let code = return_true_code();
      // Deploy our 'token'
      let () = test.provider.raw_request("anvil_setCode".into(), (token, code)).await.unwrap();
      let call =
        TransactionRequest::default().to(token).input(TransactionInput::new(vec![].into()));
      // Check it returns the expected result
      assert_eq!(
        test.provider.call(call.clone()).await.unwrap().as_ref(),
        U256::from(1).abi_encode().as_slice()
      );
      // Check it has the expected gas cost (16 is documented in `return_true_code`)
      assert_eq!(test.provider.estimate_gas(call).await.unwrap(), 21_000 + 16);
    }

    let (gas, fee) =
      test.router.execute_gas_and_fee(Coin::Erc20(token), U256::from(0), &[].as_slice().into());
    let (_tx, gas_used) = test.execute(Coin::Erc20(token), fee, [].as_slice().into(), vec![]).await;
    const UNUSED_GAS: u64 = Router::GAS_FOR_ERC20_CALL - 16;
    assert_eq!(gas_used + UNUSED_GAS, gas);
  }
}

#[tokio::test]
async fn test_eth_address_out_instruction() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  let mut rand_address = [0xff; 20];
  OsRng.fill_bytes(&mut rand_address);
  let amount_out = U256::from(2);
  let out_instructions =
    OutInstructions::from([(SeraiEthereumAddress::Address(rand_address), amount_out)].as_slice());

  let (gas, fee) = test.router.execute_gas_and_fee(Coin::Ether, U256::from(1), &out_instructions);

  let () = test
    .provider
    .raw_request("anvil_setBalance".into(), (test.router.address(), amount_out + fee))
    .await
    .unwrap();

  let (tx, gas_used) = test.execute(Coin::Ether, fee, out_instructions, vec![true]).await;
  const UNUSED_GAS: u64 = 2 * revm::interpreter::gas::CALL_STIPEND;
  assert_eq!(gas_used + UNUSED_GAS, gas);

  assert_eq!(test.provider.get_balance(test.router.address()).await.unwrap(), U256::from(0));
  let minted_to_sender = u128::from(tx.tx().gas_limit) * tx.tx().gas_price;
  let spent_by_sender = u128::from(gas_used) * tx.tx().gas_price;
  assert_eq!(
    test.provider.get_balance(tx.recover_signer().unwrap()).await.unwrap() -
      U256::from(minted_to_sender - spent_by_sender),
    U256::from(fee)
  );
  assert_eq!(test.provider.get_balance(rand_address.into()).await.unwrap(), amount_out);
}

#[tokio::test]
async fn test_erc20_address_out_instruction() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  let erc20 = Erc20::deploy(&test).await;
  let coin = Coin::Erc20(erc20.address());

  let mut rand_address = [0xff; 20];
  OsRng.fill_bytes(&mut rand_address);
  let amount_out = U256::from(2);
  let out_instructions =
    OutInstructions::from([(SeraiEthereumAddress::Address(rand_address), amount_out)].as_slice());

  let (gas, fee) = test.router.execute_gas_and_fee(coin, U256::from(1), &out_instructions);

  // Mint to the Router the necessary amount of the ERC20
  erc20.mint(&test, test.router.address(), amount_out + fee).await;

  let (tx, gas_used) = test.execute(coin, fee, out_instructions, vec![true]).await;
  // Uses traces due to the complexity of modeling Erc20::transfer
  let unused_gas = test.gas_unused_by_calls(&tx).await;
  assert_eq!(gas_used + unused_gas, gas);

  assert_eq!(erc20.balance_of(&test, test.router.address()).await, U256::from(0));
  assert_eq!(erc20.balance_of(&test, tx.recover_signer().unwrap()).await, U256::from(fee));
  assert_eq!(erc20.balance_of(&test, rand_address.into()).await, amount_out);
}

#[tokio::test]
async fn test_eth_code_out_instruction() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;
  let () = test
    .provider
    .raw_request("anvil_setBalance".into(), (test.router.address(), 1_000_000))
    .await
    .unwrap();

  let code = return_true_code();
  let amount_out = U256::from(2);
  let out_instructions = OutInstructions::from(
    [(
      SeraiEthereumAddress::Contract(ContractDeployment::new(50_000, code.clone()).unwrap()),
      amount_out,
    )]
    .as_slice(),
  );

  let (gas, fee) = test.router.execute_gas_and_fee(Coin::Ether, U256::from(1), &out_instructions);
  let (tx, gas_used) = test.execute(Coin::Ether, fee, out_instructions, vec![true]).await;

  // We use call-traces here to determine how much gas was allowed but unused due to the complexity
  // of modeling the call to the Router itself and the following CREATE
  let unused_gas = test.gas_unused_by_calls(&tx).await;
  assert_eq!(gas_used + unused_gas, gas);

  assert_eq!(
    test.provider.get_balance(test.router.address()).await.unwrap(),
    U256::from(1_000_000) - amount_out - fee
  );
  let minted_to_sender = u128::from(tx.tx().gas_limit) * tx.tx().gas_price;
  let spent_by_sender = u128::from(gas_used) * tx.tx().gas_price;
  assert_eq!(
    test.provider.get_balance(tx.recover_signer().unwrap()).await.unwrap() -
      U256::from(minted_to_sender - spent_by_sender),
    U256::from(fee)
  );
  let deployed = test.router.address().create(1);
  assert_eq!(test.provider.get_balance(deployed).await.unwrap(), amount_out);
  // The init code we use returns true, which will become the deployed contract's code
  assert_eq!(test.provider.get_code_at(deployed).await.unwrap().to_vec(), true.abi_encode());
}

#[tokio::test]
async fn test_eth_code_out_instruction_reverts() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;
  let () = test
    .provider
    .raw_request("anvil_setBalance".into(), (test.router.address(), 1_000_000))
    .await
    .unwrap();

  // [REVERT], which will cause `executeArbitraryCode`'s call to CREATE to fail
  let code = vec![0xfd];
  let amount_out = U256::from(0);
  let out_instructions = OutInstructions::from(
    [(
      SeraiEthereumAddress::Contract(ContractDeployment::new(50_000, code.clone()).unwrap()),
      amount_out,
    )]
    .as_slice(),
  );

  let (gas, fee) = test.router.execute_gas_and_fee(Coin::Ether, U256::from(1), &out_instructions);
  let (tx, gas_used) = test.execute(Coin::Ether, fee, out_instructions, vec![true]).await;

  let unused_gas = test.gas_unused_by_calls(&tx).await;
  assert_eq!(gas_used + unused_gas, gas);
}

#[tokio::test]
async fn test_erc20_code_out_instruction() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  let erc20 = Erc20::deploy(&test).await;
  let coin = Coin::Erc20(erc20.address());

  let code = return_true_code();
  let amount_out = U256::from(2);
  let out_instructions = OutInstructions::from(
    [(SeraiEthereumAddress::Contract(ContractDeployment::new(50_000, code).unwrap()), amount_out)]
      .as_slice(),
  );

  let (gas, fee) = test.router.execute_gas_and_fee(coin, U256::from(1), &out_instructions);

  // Mint to the Router the necessary amount of the ERC20
  erc20.mint(&test, test.router.address(), amount_out + fee).await;

  let (tx, gas_used) = test.execute(coin, fee, out_instructions, vec![true]).await;

  let unused_gas = test.gas_unused_by_calls(&tx).await;
  assert_eq!(gas_used + unused_gas, gas);

  assert_eq!(erc20.balance_of(&test, test.router.address()).await, U256::from(amount_out));
  assert_eq!(erc20.balance_of(&test, tx.recover_signer().unwrap()).await, U256::from(fee));
  let deployed = test.router.address().create(1);
  assert_eq!(erc20.router_approval(&test, deployed).await, amount_out);
  assert_eq!(test.provider.get_code_at(deployed).await.unwrap().to_vec(), true.abi_encode());
}

#[tokio::test]
async fn test_result_decoding() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  // Create three OutInstructions, where the last one errors
  let out_instructions = OutInstructions::from(
    [
      (SeraiEthereumAddress::Address([0; 20]), U256::from(0)),
      (SeraiEthereumAddress::Address([0; 20]), U256::from(0)),
      (SeraiEthereumAddress::Contract(ContractDeployment::new(0, vec![]).unwrap()), U256::from(0)),
    ]
    .as_slice(),
  );

  let (gas, fee) = test.router.execute_gas_and_fee(Coin::Ether, U256::from(0), &out_instructions);

  // We should decode these in the correct order (not `false, true, true`)
  let (_tx, gas_used) =
    test.execute(Coin::Ether, fee, out_instructions, vec![true, true, false]).await;
  // We don't check strict equality as we don't know how much gas was used by the reverted call
  // (even with the trace), solely that it used less than or equal to the limit
  assert!(gas_used <= gas);
}

#[tokio::test]
async fn test_reentrancy() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  const BYTECODE: &[u8] = {
    const BYTECODE_HEX: &[u8] = include_bytes!(concat!(
      env!("OUT_DIR"),
      "/serai-processor-ethereum-router/tests/Reentrancy.bin"
    ));
    const BYTECODE: [u8; BYTECODE_HEX.len() / 2] =
      match alloy_core::primitives::hex::const_decode_to_array::<{ BYTECODE_HEX.len() / 2 }>(
        BYTECODE_HEX,
      ) {
        Ok(bytecode) => bytecode,
        Err(_) => panic!("Reentrancy.bin did not contain valid hex"),
      };
    &BYTECODE
  };

  let out_instructions = OutInstructions::from(
    [(
      // The Reentrancy contract, in its constructor, will re-enter and verify the proper error is
      // returned
      SeraiEthereumAddress::Contract(ContractDeployment::new(50_000, BYTECODE.to_vec()).unwrap()),
      U256::from(0),
    )]
    .as_slice(),
  );

  let (gas, fee) = test.router.execute_gas_and_fee(Coin::Ether, U256::from(0), &out_instructions);
  let (_tx, gas_used) = test.execute(Coin::Ether, fee, out_instructions, vec![true]).await;
  // Even though this doesn't have failed `OutInstruction`s, our logic is incomplete upon any
  // failed internal calls for some reason. That's fine, as the gas yielded is still the worst-case
  // (which this isn't a counter-example to) and is validated to be the worst-case, but is peculiar
  assert!(gas_used <= gas);
}

#[tokio::test]
async fn fuzz_test_out_instructions_gas() {
  for _ in 0 .. 100 {
    let mut test = Test::new().await;
    test.confirm_next_serai_key().await;

    // Generate a random OutInstructions
    let mut out_instructions = vec![];
    let mut prior_addresses = vec![];
    for _ in 0 .. (OsRng.next_u64() % 50) {
      let amount_out = U256::from(OsRng.next_u64() % 2);
      if (OsRng.next_u64() % 2) == 1 {
        let mut code = return_true_code();

        // Extend this with random data to make it somewhat random, despite the constant returned
        // code (though the estimator will never run the initcode and realize that)
        let ext = vec![0; usize::try_from(OsRng.next_u64() % 400).unwrap()];
        code.extend(&ext);

        out_instructions.push((
          SeraiEthereumAddress::Contract(ContractDeployment::new(100_000, code).unwrap()),
          amount_out,
        ));
      } else {
        // Occasionally reuse addresses (cold/warm slots)
        let address = if (!prior_addresses.is_empty()) && ((OsRng.next_u64() % 2) == 1) {
          prior_addresses[usize::try_from(
            OsRng.next_u64() % u64::try_from(prior_addresses.len()).unwrap(),
          )
          .unwrap()]
        } else {
          let mut rand_address = [0; 20];
          OsRng.fill_bytes(&mut rand_address);
          prior_addresses.push(rand_address);
          rand_address
        };
        out_instructions.push((SeraiEthereumAddress::Address(address), amount_out));
      }
    }
    let out_instructions_original = out_instructions.clone();
    let out_instructions = OutInstructions::from(out_instructions.as_slice());

    // Randomly decide the coin
    let coin = if (OsRng.next_u64() % 2) == 1 {
      let () = test
        .provider
        .raw_request("anvil_setBalance".into(), (test.router.address(), 1_000_000_000))
        .await
        .unwrap();
      Coin::Ether
    } else {
      let erc20 = Erc20::deploy(&test).await;
      erc20.mint(&test, test.router.address(), U256::from(1_000_000_000)).await;
      Coin::Erc20(erc20.address())
    };

    let fee_per_gas = U256::from(1) + U256::from(OsRng.next_u64() % 10);
    let (gas, fee) = test.router.execute_gas_and_fee(coin, fee_per_gas, &out_instructions);
    // All of these should have succeeded
    let (tx, gas_used) =
      test.execute(coin, fee, out_instructions.clone(), vec![true; out_instructions.0.len()]).await;
    let unused_gas = test.gas_unused_by_calls(&tx).await;
    assert_eq!(
      gas_used + unused_gas,
      gas,
      "{coin:?} {fee_per_gas:?} {out_instructions_original:?}"
    );
  }
}

#[tokio::test]
async fn test_gas_increases_then_decreases() {
  /*
    This specific batch of `OutInstruction`s causes the gas to be initially calculated, and then
    increase as the proper fee is written in (due to the increased amount of non-zero bytes). But
    then, as the fee is updated until the final fee no longer increases the gas used, the gas
    actually goes *back down*. To then derive the fee from this reduced gas causes the gas to go
    back up.

    A prior version of this library would return the reduced amount of gas fee in this edge case,
    which only rarely appeared via the fuzz test (yet did once, yielding this). Then, it'd derive
    the fee from it, and expect the realized transaction to have parity (causing a test failure as
    it didn't). Now, `execute_gas` is `execute_gas_and_fee`, yielding both the gas which is
    expected *and the fee for it*. This fee is guaranteed to cost the reported amount of gas,
    resolving this issue.
  */
  let out_instructions = vec![(
    SeraiEthereumAddress::Contract(ContractDeployment::new(100_240, vec![]).unwrap()),
    U256::from(1u8),
  )];

  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  let out_instructions = OutInstructions::from(out_instructions.as_slice());

  let coin = {
    let () = test
      .provider
      .raw_request("anvil_setBalance".into(), (test.router.address(), 1_000_000_000))
      .await
      .unwrap();
    Coin::Ether
  };

  let fee_per_gas = U256::from(1);
  let (gas, fee) = test.router.execute_gas_and_fee(coin, fee_per_gas, &out_instructions);
  assert!((U256::from(gas) * fee_per_gas) != fee);
  let (tx, gas_used) =
    test.execute(coin, fee, out_instructions.clone(), vec![true; out_instructions.0.len()]).await;
  let unused_gas = test.gas_unused_by_calls(&tx).await;
  assert_eq!(gas_used + unused_gas, gas);
}
