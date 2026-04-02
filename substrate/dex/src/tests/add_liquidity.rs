use super::*;

#[test]
fn add_liquidity() {
  let mut ext = new_test_ext();
  let state_version = ext.state_version;
  ext.execute_with(|| {
    Core::start_transaction(0);

    let root_at_start = sp_io::storage::root(state_version);

    let alice = SeraiAddress::from(Pair::generate().0.public());

    let sri_coin = Coin::Serai;
    let sri_amount = Amount(200_000);
    let balance = Balance { coin: sri_coin, amount: sri_amount };

    let ext_coin = ExternalCoin::Bitcoin;
    let ext_amount = Amount(100_000);
    let ext_balance = ExternalBalance { coin: ext_coin, amount: ext_amount };

    Coins::mint(alice, balance).unwrap();
    Coins::mint(alice, ext_balance.into()).unwrap();

    // Adding a trivial amount of liquidity should fail since the pool has yet to initialize
    {
      let root = sp_io::storage::root(state_version);
      // Check `sp_io::TestExternalities` doesn't stub this and it does update upon change
      assert!(root_at_start != root);
      assert_eq!(
        Dex::add_liquidity(
          Some(alice).into(),
          ext_coin,
          Amount(1),
          Amount(1),
          Amount(1),
          Amount(1)
        )
        .unwrap_err(),
        DispatchError::from(crate::Error::<Test>::InvalidLiquidity)
      );
      // This shouldn't cause _any_ changes to the storage
      assert_eq!(root, sp_io::storage::root(state_version));
    }

    // Initializing the pool should work
    let mut expected_events = vec![];
    {
      Dex::add_liquidity(
        Some(alice).into(),
        ext_coin,
        sri_amount,
        ext_amount,
        Amount(1),
        Amount(1),
      )
      .unwrap();
      assert_eq!(Coins::balance(alice, sri_coin), Amount(0));
      assert_eq!(Coins::balance(alice, ext_coin), Amount(0));
      assert_eq!(Coins::balance(serai_abi::dex::address(ext_coin), sri_coin), sri_amount);
      assert_eq!(Coins::balance(serai_abi::dex::address(ext_coin), ext_coin), ext_amount);
      let liquidity_tokens =
        ExternalBalance { coin: ext_coin, amount: Amount((sri_amount.0 * ext_amount.0).isqrt()) };
      assert_eq!(LiquidityTokens::balance(alice, ext_coin), liquidity_tokens.amount);

      expected_events.push(Event::Dex(serai_abi::dex::Event::LiquidityAddition {
        recipient: alice,
        liquidity_tokens,
        sri_amount,
        external_coin_amount: ext_amount,
      }));

      let events = Core::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, Event::Dex(_)))
        .collect::<Vec<_>>();
      assert_eq!(&events, &expected_events);
    }

    // Adding more liquidity should work, even when not following the existing ratio
    for (sri_denom, ext_denom) in [(1, 1), (1, 2), (2, 1)] {
      let sri_amount =
        Amount(Coins::balance(serai_abi::dex::address(ext_coin), sri_coin).0 / sri_denom);
      let ext_amount =
        Amount(Coins::balance(serai_abi::dex::address(ext_coin), ext_coin).0 / ext_denom);

      let bob = SeraiAddress::from(Pair::generate().0.public());
      Coins::mint(bob, Balance { coin: sri_coin, amount: sri_amount }).unwrap();
      Coins::mint(bob, Balance { coin: ext_coin.into(), amount: ext_amount }).unwrap();

      let prior_liquidity_tokens = LiquidityTokens::supply(ext_coin).0;
      Dex::add_liquidity(Some(bob).into(), ext_coin, sri_amount, ext_amount, Amount(1), Amount(1))
        .unwrap();
      let sri_amount_added = Amount(sri_amount.0 - Coins::balance(bob, sri_coin).0);
      assert!(sri_amount_added <= sri_amount);
      let ext_amount_added = Amount(ext_amount.0 - Coins::balance(bob, ext_coin).0);
      assert!(ext_amount_added <= ext_amount);
      let liquidity_tokens_amount_for_sri =
        Amount((sri_amount_added.0 * prior_liquidity_tokens) / sri_amount.0);
      let liquidity_tokens_amount_for_ext =
        Amount((ext_amount_added.0 * prior_liquidity_tokens) / ext_amount.0);
      let liquidity_tokens = ExternalBalance {
        coin: ext_coin,
        amount: liquidity_tokens_amount_for_sri.min(liquidity_tokens_amount_for_ext),
      };
      assert_eq!(LiquidityTokens::balance(bob, ext_coin), liquidity_tokens.amount);

      expected_events.push(Event::Dex(serai_abi::dex::Event::LiquidityAddition {
        recipient: bob,
        liquidity_tokens,
        sri_amount: sri_amount_added,
        external_coin_amount: ext_amount_added,
      }));

      let events = Core::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, Event::Dex(_)))
        .collect::<Vec<_>>();
      assert_eq!(&events, &expected_events);
    }

    // Adding liquidity shouldn't occur when the minimum isn't respected
    for (sri, ext) in [(1, 0), (0, 1)] {
      let sri_amount =
        Amount(Coins::balance(serai_abi::dex::address(ext_coin), sri_coin).0 * sri).max(Amount(1));
      let ext_amount =
        Amount(Coins::balance(serai_abi::dex::address(ext_coin), ext_coin).0 * ext).max(Amount(1));

      let bob = SeraiAddress::from(Pair::generate().0.public());
      Coins::mint(bob, Balance { coin: sri_coin, amount: sri_amount }).unwrap();
      Coins::mint(bob, Balance { coin: ext_coin.into(), amount: ext_amount }).unwrap();

      let root = sp_io::storage::root(state_version);
      assert_eq!(
        Dex::add_liquidity(
          Some(bob).into(),
          ext_coin,
          sri_amount,
          ext_amount,
          sri_amount,
          ext_amount
        )
        .unwrap_err(),
        DispatchError::from(crate::Error::<Test>::Unsatisfied)
      );
      // Ensure this didn't cause any modification to the storage
      assert_eq!(root, sp_io::storage::root(state_version));
    }
  });
}
