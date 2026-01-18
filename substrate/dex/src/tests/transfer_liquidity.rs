use super::*;

#[test]
fn transfer_liquidity() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    let alice = SeraiAddress::from(Pair::generate().0.public());
    let bob = SeraiAddress::from(Pair::generate().0.public());
    let coin = ExternalCoin::Bitcoin;
    let amount = Amount(1);
    let balance = ExternalBalance { coin, amount };

    /*
      Because this internally defers to `serai_coins_pallet`, we only test the
      liquidity-token-specific functionality here. That's checking the instance, lack of `Coins`
      events, and the `Dex` event is as expected.
    */

    LiquidityTokens::mint(alice, balance.into()).unwrap();

    assert_eq!(LiquidityTokens::balance(alice, coin), amount);
    assert_eq!(LiquidityTokens::balance(bob, coin), Amount(0));
    Dex::transfer_liquidity(Some(alice).into(), bob, balance).unwrap();
    assert_eq!(LiquidityTokens::balance(alice, coin), Amount(0));
    assert_eq!(LiquidityTokens::balance(bob, coin), amount);

    let mut events = vec![];
    for event in Core::events()
      .iter()
      .flat_map(IntoIterator::into_iter)
      .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
    {
      assert!(!matches!(event, Event::Coins(_)), "interaction with DEX emitted `Coins` event?");
      if matches!(event, Event::Dex(_)) {
        events.push(event);
      }
    }
    assert_eq!(
      events,
      vec![Event::Dex(serai_abi::dex::Event::LiquidityTransfer {
        from: alice,
        to: bob,
        liquidity_tokens: balance
      })]
    );
  });
}
