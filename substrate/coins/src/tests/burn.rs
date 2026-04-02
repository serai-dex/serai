use super::*;

#[test]
fn burn() {
  let mut ext = new_test_ext(vec![]);
  let state_version = ext.state_version;
  ext.execute_with(|| {
    Core::start_transaction(0);

    let root_at_start = sp_io::storage::root(state_version);

    let mut state = State::new();

    let coin = Coin::Serai;
    let to = SeraiAddress::from(Pair::generate().0.public());
    let balance = Balance { coin, amount: Amount(5) };
    Coins::mint(to, balance).unwrap();
    state.mint::<CoinsInstance>(to, balance);

    // Burning `0` should work
    {
      let balance = Balance { coin, amount: Amount(0) };
      #[expect(clippy::disallowed_methods)]
      Coins::burn(Some(to).into(), balance).unwrap();
      state.burn::<CoinsInstance>(to, balance);
      assert_eq!(Coins::supply(coin), Amount(5));
      assert_eq!(Coins::balance(to, coin), Amount(5));
    }

    // Burning a non-zero amount should work
    {
      let balance = Balance { coin, amount: Amount(1) };
      #[expect(clippy::disallowed_methods)]
      Coins::burn(Some(to).into(), balance).unwrap();
      state.burn::<CoinsInstance>(to, balance);
      assert_eq!(Coins::supply(coin), Amount(4));
      assert_eq!(Coins::balance(to, coin), Amount(4));
    }

    // Burning more than one has should fail, with no changes to the state
    {
      let root = sp_io::storage::root(state_version);
      // Check `sp_io::TestExternalities` doesn't stub this and it does update upon change
      assert!(root_at_start != root);
      assert!({
        #[expect(clippy::disallowed_methods)]
        Coins::burn(Some(to).into(), Balance { coin, amount: Amount(5) }).is_err()
      });
      assert_eq!(sp_io::storage::root(state_version), root);
    }

    // Burning for another instance should behave the same, but without an event associated
    {
      let events = Core::events();
      let balance = Balance { coin: ExternalCoin::Ether.into(), amount: Amount(1) };
      LiquidityTokens::mint(to, balance).unwrap();
      state.mint::<LiquidityTokensInstance>(to, balance);
      #[expect(clippy::disallowed_methods)]
      LiquidityTokens::burn_fn(to, balance).unwrap();
      state.burn::<LiquidityTokensInstance>(to, balance);
      // Check the events haven't changed, meaning no event was emitted
      assert_eq!(events, Core::events());
    }

    /*
      As an edge case, even burning zero from someone without a balance, for a coin without a
      supply, should work (as their balance is still >= the amount burnt).
    */
    {
      let balance = Balance { coin: ExternalCoin::Dai.into(), amount: Amount(0) };
      #[expect(clippy::disallowed_methods)]
      LiquidityTokens::burn_fn(to, balance).unwrap();
      state.burn::<LiquidityTokensInstance>(to, balance);
    }
  });
}

#[test]
fn burn_with_instruction() {
  let mut ext = new_test_ext(vec![]);
  let state_version = ext.state_version;
  ext.execute_with(|| {
    Core::start_transaction(0);

    let mut state = State::new();

    let to = SeraiAddress::from(Pair::generate().0.public());

    let instruction = OutInstruction::Transfer(ExternalAddress::try_from(vec![]).unwrap());
    let coin = ExternalCoin::Bitcoin;
    let balance = ExternalBalance { coin, amount: Amount(1) };
    let out_instruction = OutInstructionWithBalance { instruction, balance };

    // Burning with an instruction should work
    {
      Coins::mint(to, balance.into()).unwrap();
      state.mint::<CoinsInstance>(to, balance.into());

      #[expect(clippy::disallowed_methods)]
      Coins::burn_with_instruction(Some(to).into(), out_instruction.clone()).unwrap();
      state.burn_with_instruction::<CoinsInstance>(to, out_instruction.clone());

      assert_eq!(Coins::supply(coin), Amount(0));
      assert_eq!(Coins::balance(to, coin), Amount(0));
    }

    // Burning with an instruction and the wrong instance should error, with no state changes
    {
      let root = sp_io::storage::root(state_version);

      assert_eq!(
        {
          #[expect(clippy::disallowed_methods)]
          LiquidityTokens::burn_with_instruction(Some(to).into(), out_instruction.clone())
            .unwrap_err()
        },
        frame_support::pallet_prelude::DispatchError::from(
          crate::Error::<Test, LiquidityTokensInstance>::BurnWithInstructionNotAllowed
        )
      );

      assert_eq!(sp_io::storage::root(state_version), root);
    }

    // Burning when halted should error, with no state changes
    {
      sp_io::storage::set(&("BurnWithInstruction", balance.coin.network()).encode(), &[]);

      Coins::mint(to, balance.into()).unwrap();
      state.mint::<CoinsInstance>(to, balance.into());

      let root = sp_io::storage::root(state_version);

      assert_eq!(
        {
          #[expect(clippy::disallowed_methods)]
          Coins::burn_with_instruction(Some(to).into(), out_instruction).unwrap_err()
        },
        frame_support::pallet_prelude::DispatchError::from(
          crate::Error::<Test, CoinsInstance>::BurnWithInstructionNotAllowed
        )
      );

      assert_eq!(sp_io::storage::root(state_version), root);
    }
  });
}
