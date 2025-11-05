use std::collections::HashSet;

use alloy_core::primitives::U256;
use alloy_sol_types::SolCall;

use alloy_consensus::{TxLegacy, Signed};

use serai_primitives::{
  address::SeraiAddress,
  instructions::{InInstruction as SeraiInInstruction, RefundableInInstruction},
};

use ethereum_primitives::LogIndex;

use crate::{InInstruction, tests::*};

impl Test {
  pub(crate) fn in_instruction() -> RefundableInInstruction {
    RefundableInInstruction {
      return_address: None,
      instruction: SeraiInInstruction::Transfer { to: SeraiAddress([0xff; 32]) },
    }
  }

  pub(crate) fn eth_in_instruction_tx(&self) -> (Coin, U256, RefundableInInstruction, TxLegacy) {
    let coin = Coin::Ether;
    let amount = U256::from(1);
    let shorthand = Self::in_instruction();

    let mut tx = self.router.in_instruction(coin, amount, &shorthand);
    tx.gas_limit = 1_000_000;
    tx.gas_price = 100_000_000_000;

    (coin, amount, shorthand, tx)
  }

  pub(crate) async fn publish_in_instruction_tx(
    &self,
    tx: Signed<TxLegacy>,
    coin: Coin,
    amount: U256,
    shorthand: &RefundableInInstruction,
  ) {
    let receipt = ethereum_test_primitives::publish_tx(&self.provider, tx.clone()).await;
    assert!(receipt.status());

    let block = receipt.block_number.unwrap();

    if matches!(coin, Coin::Erc20(_)) {
      // If we don't whitelist this token, we shouldn't be yielded an InInstruction
      let in_instructions =
        self.router.in_instructions_unordered(block ..= block, &HashSet::new()).await.unwrap();
      assert!(in_instructions.is_empty());
    }

    let in_instructions = self
      .router
      .in_instructions_unordered(
        block ..= block,
        &if let Coin::Erc20(token) = coin { HashSet::from([token]) } else { HashSet::new() },
      )
      .await
      .unwrap();
    assert_eq!(in_instructions.len(), 1);

    let in_instruction_log_index = receipt.inner.logs().iter().find_map(|log| {
      (log.topics().first() == Some(&crate::InInstructionEvent::SIGNATURE_HASH))
        .then(|| log.log_index.unwrap())
    });
    // If this isn't an InInstruction event, it'll be a top-level transfer event
    let log_index = in_instruction_log_index.unwrap_or(0);

    assert_eq!(
      in_instructions[0],
      InInstruction {
        id: LogIndex { block_hash: *receipt.block_hash.unwrap(), index_within_block: log_index },
        transaction_hash: **tx.hash(),
        from: tx.recover_signer().unwrap(),
        coin,
        amount,
        data: borsh::to_vec(&shorthand).unwrap(),
      }
    );
  }
}

#[tokio::test]
async fn test_no_in_instruction_before_key() {
  let test = Test::new().await;

  // We shouldn't be able to publish `InInstruction`s before publishing a key
  let (_coin, _amount, _shorthand, tx) = test.eth_in_instruction_tx();
  assert!(matches!(
    test.call_and_decode_err(tx).await,
    IRouterErrors::SeraiKeyWasNone(IRouter::SeraiKeyWasNone {})
  ));
}

#[tokio::test]
async fn test_eth_in_instruction() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  let (coin, amount, shorthand, tx) = test.eth_in_instruction_tx();

  // This should fail if the value mismatches the amount
  {
    let mut tx = tx.clone();
    tx.value = U256::ZERO;
    assert!(matches!(
      test.call_and_decode_err(tx).await,
      IRouterErrors::AmountMismatchesMsgValue(IRouter::AmountMismatchesMsgValue {})
    ));
  }

  let tx = ethereum_primitives::deterministically_sign(tx);
  test.publish_in_instruction_tx(tx, coin, amount, &shorthand).await;
}

#[tokio::test]
async fn test_erc20_router_in_instruction() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  let erc20 = Erc20::deploy(&test).await;

  let coin = Coin::Erc20(erc20.address());
  let amount = U256::from(1);
  let shorthand = Test::in_instruction();

  // The provided `in_instruction` function will use a top-level transfer for ERC20 InInstructions,
  // so we have to manually write this call
  let tx = TxLegacy {
    chain_id: None,
    nonce: 0,
    gas_price: 100_000_000_000,
    gas_limit: 1_000_000,
    to: test.router.address().into(),
    value: U256::ZERO,
    input: crate::abi::inInstructionCall::new((
      coin.into(),
      amount,
      borsh::to_vec(&shorthand).unwrap().into(),
    ))
    .abi_encode()
    .into(),
  };

  // If no `approve` was granted, this should fail
  assert!(matches!(
    test.call_and_decode_err(tx.clone()).await,
    IRouterErrors::TransferFromFailed(IRouter::TransferFromFailed {})
  ));

  let tx = ethereum_primitives::deterministically_sign(tx);
  {
    let signer = tx.recover_signer().unwrap();
    erc20.mint(&test, signer, amount).await;
    erc20.approve(&test, signer, test.router.address(), amount).await;
  }

  test.publish_in_instruction_tx(tx, coin, amount, &shorthand).await;
}

#[tokio::test]
async fn test_erc20_top_level_transfer_in_instruction() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  let erc20 = Erc20::deploy(&test).await;

  let coin = Coin::Erc20(erc20.address());
  let amount = U256::from(1);
  let shorthand = Test::in_instruction();

  let mut tx = test.router.in_instruction(coin, amount, &shorthand);
  tx.gas_price = 100_000_000_000;
  tx.gas_limit = 1_000_000;

  let tx = ethereum_primitives::deterministically_sign(tx);
  erc20.mint(&test, tx.recover_signer().unwrap(), amount).await;
  test.publish_in_instruction_tx(tx, coin, amount, &shorthand).await;
}
