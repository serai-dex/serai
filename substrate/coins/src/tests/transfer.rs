use super::*;

#[test]
fn transfer() {
  let mut ext = new_test_ext(vec![]);
  let state_version = ext.state_version;
  ext.execute_with(|| {
    Core::start_transaction(0);

    let root_at_start = sp_io::storage::root(state_version);

    let mut state = State::new();

    let alice = SeraiAddress::from(Pair::generate().0.public());
    let bob = SeraiAddress::from(Pair::generate().0.public());
    let coin = Coin::Serai;

    // Transferring `0` should always work
    {
      let balance = Balance { coin, amount: Amount(0) };
      #[expect(clippy::disallowed_methods)]
      Coins::transfer(Some(alice).into(), bob, balance).unwrap();
      state.transfer::<CoinsInstance>(alice, bob, balance);
      assert_eq!(Coins::supply(coin), Amount(0));
      assert_eq!(Coins::balance(alice, coin), Amount(0));
      assert_eq!(Coins::balance(bob, coin), Amount(0));
    }

    {
      let amount = Amount(5);
      let balance = Balance { coin, amount };
      Coins::mint(alice, balance).unwrap();
      state.mint::<CoinsInstance>(alice, balance);
    }

    // Transferring an amount one has should work
    {
      let balance = Balance { coin, amount: Amount(3) };
      #[expect(clippy::disallowed_methods)]
      Coins::transfer(Some(alice).into(), bob, balance).unwrap();
      state.transfer::<CoinsInstance>(alice, bob, balance);
      assert_eq!(Coins::supply(coin), Amount(5));
      assert_eq!(Coins::balance(alice, coin), Amount(2));
      assert_eq!(Coins::balance(bob, coin), Amount(3));
    }

    // Transferring more than one has should fail, with no changes to the state
    {
      let root = sp_io::storage::root(state_version);
      assert_ne!(root, root_at_start);
      assert!({
        #[expect(clippy::disallowed_methods)]
        Coins::transfer(Some(alice).into(), bob, Balance { coin, amount: Amount(5) }).is_err()
      });
      assert_eq!(sp_io::storage::root(state_version), root);
    }

    // Transferring for another instance should behave the same, but without an event associated
    {
      let events = Core::events();

      let balance = Balance { coin, amount: Amount(1) };
      LiquidityTokens::mint(alice, balance).unwrap();
      state.mint::<LiquidityTokensInstance>(alice, balance);

      #[expect(clippy::disallowed_methods)]
      LiquidityTokens::transfer(Some(alice).into(), bob, balance).unwrap();
      state.transfer::<LiquidityTokensInstance>(alice, bob, balance);
      assert_eq!(LiquidityTokens::supply(coin), Amount(1));
      assert_eq!(LiquidityTokens::balance(alice, coin), Amount(0));
      assert_eq!(LiquidityTokens::balance(bob, coin), Amount(1));

      // Check the events haven't changed, meaning no event was emitted
      assert_eq!(events, Core::events());
    }
  });
}
