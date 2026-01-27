use super::*;

#[test]
fn remove_liquidity() {
  let mut ext = new_test_ext();
  let state_version = ext.state_version;
  ext.execute_with(|| {
    Core::start_transaction(0);

    let alice = SeraiAddress::from(Pair::generate().0.public());

    let sri_coin = Coin::Serai;
    let sri_amount = Amount(400_000);
    let balance = Balance { coin: sri_coin, amount: sri_amount };

    let ext_coin = ExternalCoin::Bitcoin;
    let ext_amount = Amount(100_000);
    let ext_balance = ExternalBalance { coin: ext_coin, amount: ext_amount };

    Coins::mint(alice, balance).unwrap();
    Coins::mint(alice, ext_balance.into()).unwrap();

    // Initialize the pool
    let mut expected_events = vec![];
    let liquidity_tokens = {
      Dex::add_liquidity(
        Some(alice).into(),
        ext_coin,
        sri_amount,
        ext_amount,
        Amount(1),
        Amount(1),
      )
      .unwrap();
      let liquidity_tokens =
        ExternalBalance { coin: ext_coin, amount: LiquidityTokens::balance(alice, ext_coin) };

      expected_events.push(Event::Dex(serai_abi::dex::Event::LiquidityAddition {
        recipient: alice,
        liquidity_tokens,
        sri_amount,
        external_coin_amount: ext_amount,
      }));

      liquidity_tokens
    };

    // We should be able to remove liquidity
    {
      let expected_sri = Amount(Coins::balance(serai_abi::dex::address(ext_coin), sri_coin).0 / 10);
      let expected_ext = Amount(Coins::balance(serai_abi::dex::address(ext_coin), ext_coin).0 / 10);
      let removed =
        ExternalBalance { coin: ext_coin, amount: Amount(liquidity_tokens.amount.0 / 10) };
      Dex::remove_liquidity(Some(alice).into(), removed, Amount(1), Amount(1)).unwrap();
      assert_eq!(Coins::balance(alice, sri_coin), expected_sri);
      assert_eq!(Coins::balance(alice, ext_coin), expected_ext);
      assert_eq!(
        LiquidityTokens::balance(alice, ext_coin),
        Amount(liquidity_tokens.amount.0 * 9 / 10)
      );

      expected_events.push(Event::Dex(serai_abi::dex::Event::LiquidityRemoval {
        from: alice,
        liquidity_tokens: removed,
        sri_amount: expected_sri,
        external_coin_amount: expected_ext,
      }));

      let events = Core::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, Event::Dex(_)))
        .collect::<Vec<_>>();
      assert_eq!(&events, &expected_events);
    }

    // Removing liquidity, when the minimum is unsatisfied, should so error
    for (sri, ext) in [(1, 0), (0, 1)] {
      let root = sp_io::storage::root(state_version);
      assert_eq!(
        Dex::remove_liquidity(
          Some(alice).into(),
          ExternalBalance { coin: ext_coin, amount: Amount(0) },
          Amount(sri),
          Amount(ext),
        )
        .unwrap_err(),
        DispatchError::from(crate::Error::<Test>::Unsatisfied)
      );
      // Ensure this didn't cause any modification to the storage
      assert_eq!(root, sp_io::storage::root(state_version));
    }
  });
}
