use alloy_core::primitives::{Address, U256};

use alloy_consensus::TxLegacy;

use alloy_provider::Provider;

use crate::tests::*;

impl Test {
  pub(crate) fn escape_hatch_tx(&self, escape_to: Address) -> TxLegacy {
    let msg = Router::escape_hatch_message(
      self.chain_id,
      self.router.address(),
      self.state.next_nonce,
      escape_to,
    );
    let sig = sign(self.state.key.unwrap(), &msg);
    let mut tx = self.router.escape_hatch(escape_to, &sig);
    tx.gas_limit = Router::ESCAPE_HATCH_GAS + 5_000;
    tx
  }

  pub(crate) async fn escape_hatch(&mut self) {
    let mut escape_to = [0; 20];
    OsRng.fill_bytes(&mut escape_to);
    let escape_to = Address(escape_to.into());

    // Set the code of the address to escape to so it isn't flagged as a non-contract
    let () = self.provider.raw_request("anvil_setCode".into(), (escape_to, [0])).await.unwrap();

    let mut tx = self.escape_hatch_tx(escape_to);
    tx.gas_price = 100_000_000_000;
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&self.provider, tx.clone()).await;
    assert!(receipt.status());
    // This encodes an address which has 12 bytes of padding
    assert_eq!(
      CalldataAgnosticGas::calculate(tx.tx().input.as_ref(), 12, receipt.gas_used),
      Router::ESCAPE_HATCH_GAS
    );

    {
      let block = receipt.block_number.unwrap();
      let executed = self.router.executed(block ..= block).await.unwrap();
      assert_eq!(executed.len(), 1);
      assert_eq!(executed[0], Executed::EscapeHatch { nonce: self.state.next_nonce, escape_to });
    }

    self.state.next_nonce += 1;
    self.state.escaped_to = Some(escape_to);
    self.verify_state().await;
  }

  pub(crate) fn escape_tx(&self, coin: Coin) -> TxLegacy {
    let mut tx = self.router.escape(coin);
    tx.gas_limit = 100_000;
    tx.gas_price = 100_000_000_000;
    tx
  }
}

#[tokio::test]
async fn test_escape_hatch() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  // Queue another key so the below test cases can run
  test.update_serai_key().await;

  {
    // The zero address should be invalid to escape to
    assert!(matches!(
      test.call_and_decode_err(test.escape_hatch_tx([0; 20].into())).await,
      IRouterErrors::InvalidEscapeAddress(IRouter::InvalidEscapeAddress {})
    ));
    // Empty addresses should be invalid to escape to
    assert!(matches!(
      test.call_and_decode_err(test.escape_hatch_tx([1; 20].into())).await,
      IRouterErrors::EscapeAddressWasNotAContract(IRouter::EscapeAddressWasNotAContract {})
    ));
    // Non-empty addresses without code should be invalid to escape to
    let tx = ethereum_primitives::deterministically_sign(TxLegacy {
      to: Address([1; 20].into()).into(),
      gas_limit: 21_000,
      gas_price: 100_000_000_000,
      value: U256::from(1),
      ..Default::default()
    });
    let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx.clone()).await;
    assert!(receipt.status());
    assert!(matches!(
      test.call_and_decode_err(test.escape_hatch_tx([1; 20].into())).await,
      IRouterErrors::EscapeAddressWasNotAContract(IRouter::EscapeAddressWasNotAContract {})
    ));

    // Escaping at this point in time should fail
    assert!(matches!(
      test.call_and_decode_err(test.router.escape(Coin::Ether)).await,
      IRouterErrors::EscapeHatchNotInvoked(IRouter::EscapeHatchNotInvoked {})
    ));
  }

  // Invoke the escape hatch
  test.escape_hatch().await;

  // Now that the escape hatch has been invoked, all of the following calls should fail
  {
    assert!(matches!(
      test.call_and_decode_err(test.update_serai_key_tx().1).await,
      IRouterErrors::EscapeHatchInvoked(IRouter::EscapeHatchInvoked {})
    ));
    assert!(matches!(
      test.call_and_decode_err(test.confirm_next_serai_key_tx()).await,
      IRouterErrors::EscapeHatchInvoked(IRouter::EscapeHatchInvoked {})
    ));
    assert!(matches!(
      test.call_and_decode_err(test.eth_in_instruction_tx().3).await,
      IRouterErrors::EscapeHatchInvoked(IRouter::EscapeHatchInvoked {})
    ));
    assert!(matches!(
      test
        .call_and_decode_err(test.execute_tx(Coin::Ether, U256::from(0), [].as_slice().into()).1)
        .await,
      IRouterErrors::EscapeHatchInvoked(IRouter::EscapeHatchInvoked {})
    ));
    // We reject further attempts to update the escape hatch to prevent the last key from being
    // able to switch from the honest escape hatch to siphoning via a malicious escape hatch (such
    // as after the validators represented unstake)
    assert!(matches!(
      test.call_and_decode_err(test.escape_hatch_tx(test.state.escaped_to.unwrap())).await,
      IRouterErrors::EscapeHatchInvoked(IRouter::EscapeHatchInvoked {})
    ));
  }

  // Check the escape fn itself

  // ETH
  {
    let () = test
      .provider
      .raw_request("anvil_setBalance".into(), (test.router.address(), 1))
      .await
      .unwrap();
    let tx = ethereum_primitives::deterministically_sign(test.escape_tx(Coin::Ether));
    let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx.clone()).await;
    assert!(receipt.status());

    let block = receipt.block_number.unwrap();
    assert_eq!(
      test.router.escapes(block ..= block).await.unwrap(),
      vec![Escape { coin: Coin::Ether, amount: U256::from(1) }],
    );

    assert_eq!(test.provider.get_balance(test.router.address()).await.unwrap(), U256::from(0));
    assert_eq!(
      test.provider.get_balance(test.state.escaped_to.unwrap()).await.unwrap(),
      U256::from(1)
    );
  }

  // ERC20
  {
    let erc20 = Erc20::deploy(&test).await;
    let coin = Coin::Erc20(erc20.address());
    let amount = U256::from(1);
    erc20.mint(&test, test.router.address(), amount).await;

    let tx = ethereum_primitives::deterministically_sign(test.escape_tx(coin));
    let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx.clone()).await;
    assert!(receipt.status());

    let block = receipt.block_number.unwrap();
    assert_eq!(test.router.escapes(block ..= block).await.unwrap(), vec![Escape { coin, amount }],);
    assert_eq!(erc20.balance_of(&test, test.router.address()).await, U256::from(0));
    assert_eq!(erc20.balance_of(&test, test.state.escaped_to.unwrap()).await, amount);
  }
}
