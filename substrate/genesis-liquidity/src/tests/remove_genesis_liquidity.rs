use super::*;

const ALICE: SeraiAddress = SeraiAddress([0xaa; 32]);
const COIN: ExternalCoin = ExternalCoin::Bitcoin;
const SRI_AMOUNT: Amount = Amount(2_000_000);
const COIN_AMOUNT: Amount = Amount(1_000_000);
const LP_AMOUNT: Amount = Amount(1_500_000);

fn events() -> Vec<serai_abi::Event> {
  Core::events()
    .iter()
    .flat_map(IntoIterator::into_iter)
    .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
    .collect::<Vec<_>>()
}

// TODO: All of the following tests were written quite quickly, meaning they're largely copy/pasted
// and solely testing a few different parameters against simple constants. These should be unified
// to a single comprehensive evaluator, which is passed the parameters to try, and then extended
// with a fuzz test.

#[test]
fn remove_genesis_liquidity_pre_oracle() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    Coins::mint(
      serai_abi::genesis_liquidity::address(COIN),
      Balance { coin: Coin::External(COIN), amount: COIN_AMOUNT },
    )
    .unwrap();
    GenesisLiquidityTokens::mint(
      ALICE,
      (ExternalBalance { coin: COIN, amount: COIN_AMOUNT }).into(),
    )
    .unwrap();

    let transfer = ExternalBalance { coin: COIN, amount: Amount(1_000) };

    // This should error if a minimum is unsatisfied
    GenesisLiquidity::remove_genesis_liquidity(Some(ALICE).into(), transfer, Amount(1), Amount(0))
      .unwrap_err();
    GenesisLiquidity::remove_genesis_liquidity(
      Some(ALICE).into(),
      transfer,
      Amount(0),
      Amount(1_001),
    )
    .unwrap_err();

    let events_prior = events().len();

    // But it should generally work
    GenesisLiquidity::remove_genesis_liquidity(
      Some(ALICE).into(),
      transfer,
      Amount(0),
      transfer.amount,
    )
    .unwrap();

    let new_genesis_liquidity_supply = (COIN_AMOUNT - transfer.amount).unwrap();

    let glp_address = serai_abi::genesis_liquidity::address(COIN);

    assert_eq!(GenesisLiquidityTokens::supply(COIN), new_genesis_liquidity_supply);
    assert_eq!(GenesisLiquidityTokens::balance(ALICE, COIN), new_genesis_liquidity_supply);

    assert_eq!(LiquidityTokens::supply(COIN), Amount(0));
    assert_eq!(Coins::supply(Coin::Serai), Amount(0));

    assert_eq!(Coins::supply(COIN), COIN_AMOUNT);
    assert_eq!(Coins::balance(ALICE, COIN), transfer.amount);
    assert_eq!(Coins::balance(glp_address, COIN), (COIN_AMOUNT - transfer.amount).unwrap());

    assert_eq!(
      &events()[events_prior ..],
      &[
        serai_abi::Event::Coins(serai_abi::coins::Event::Transfer {
          from: glp_address,
          to: ALICE,
          coins: Balance { coin: COIN.into(), amount: transfer.amount }
        }),
        serai_abi::Event::GenesisLiquidity(
          serai_abi::genesis_liquidity::Event::GenesisLiquidityRemoval {
            by: ALICE,
            genesis_liquidity: ExternalBalance { coin: COIN, amount: transfer.amount },
            sri_burnt: Amount(0),
            sri_yielded: Amount(0),
            external_coin_yielded: transfer.amount,
          }
        ),
      ]
    );
  });
}

fn init_oraclized() {
  Core::start_transaction(0);

  Coins::mint(serai_abi::dex::address(COIN), Balance { coin: Coin::Serai, amount: SRI_AMOUNT })
    .unwrap();
  Coins::mint(
    serai_abi::dex::address(COIN),
    Balance { coin: Coin::External(COIN), amount: COIN_AMOUNT },
  )
  .unwrap();
  LiquidityTokens::mint(
    serai_abi::genesis_liquidity::address(COIN),
    Balance { coin: Coin::External(COIN), amount: LP_AMOUNT },
  )
  .unwrap();
  GenesisLiquidityTokens::mint(ALICE, (ExternalBalance { coin: COIN, amount: COIN_AMOUNT }).into())
    .unwrap();

  crate::Oraclized::<Test>::set(Some(()));
}

#[test]
fn remove_genesis_liquidity_post_oracle() {
  new_test_ext().execute_with(|| {
    init_oraclized();

    let transfer = ExternalBalance { coin: COIN, amount: Amount(1_000) };

    // This should error if a minimum is unsatisfied
    GenesisLiquidity::remove_genesis_liquidity(Some(ALICE).into(), transfer, Amount(1), Amount(0))
      .unwrap_err();
    GenesisLiquidity::remove_genesis_liquidity(
      Some(ALICE).into(),
      transfer,
      Amount(0),
      Amount(1_001),
    )
    .unwrap_err();

    let events_prior = events().len();

    // But it should generally work
    GenesisLiquidity::remove_genesis_liquidity(
      Some(ALICE).into(),
      transfer,
      Amount(0),
      transfer.amount,
    )
    .unwrap();

    let new_genesis_liquidity_supply = (COIN_AMOUNT - transfer.amount).unwrap();

    let lp_removed = Amount(1_500);
    let new_lp_supply = (LP_AMOUNT - lp_removed).unwrap();

    let sri_burnt = Amount(2_000);
    let new_serai_supply = (SRI_AMOUNT - sri_burnt).unwrap();

    let pool_address = serai_abi::dex::address(COIN);
    let glp_address = serai_abi::genesis_liquidity::address(COIN);

    assert_eq!(GenesisLiquidityTokens::supply(COIN), new_genesis_liquidity_supply);
    assert_eq!(GenesisLiquidityTokens::balance(ALICE, COIN), new_genesis_liquidity_supply);

    assert_eq!(LiquidityTokens::supply(COIN), new_lp_supply);
    assert_eq!(LiquidityTokens::balance(glp_address, COIN), new_lp_supply);

    assert_eq!(Coins::supply(Coin::Serai), new_serai_supply);
    assert_eq!(Coins::balance(ALICE, Coin::Serai), Amount(0));
    assert_eq!(Coins::balance(pool_address, Coin::Serai), new_serai_supply);

    assert_eq!(Coins::supply(COIN), COIN_AMOUNT);
    assert_eq!(Coins::balance(ALICE, COIN), transfer.amount);
    assert_eq!(Coins::balance(pool_address, COIN), (COIN_AMOUNT - transfer.amount).unwrap());

    assert_eq!(
      &events()[events_prior ..],
      &[
        serai_abi::Event::Coins(serai_abi::coins::Event::Transfer {
          from: pool_address,
          to: glp_address,
          coins: Balance { coin: Coin::Serai, amount: sri_burnt }
        }),
        serai_abi::Event::Coins(serai_abi::coins::Event::Transfer {
          from: pool_address,
          to: glp_address,
          coins: Balance { coin: COIN.into(), amount: transfer.amount }
        }),
        serai_abi::Event::Dex(serai_abi::dex::Event::LiquidityRemoval {
          from: glp_address,
          liquidity_tokens: ExternalBalance { coin: COIN, amount: lp_removed },
          external_coin_amount: transfer.amount,
          sri_amount: sri_burnt,
        }),
        serai_abi::Event::Dex(serai_abi::dex::Event::LiquidityTransfer {
          from: glp_address,
          to: pool_address,
          liquidity_tokens: ExternalBalance { coin: COIN, amount: Amount(0) }
        }),
        serai_abi::Event::Coins(serai_abi::coins::Event::Burn {
          from: glp_address,
          coins: Balance { coin: Coin::Serai, amount: sri_burnt }
        }),
        serai_abi::Event::Coins(serai_abi::coins::Event::Transfer {
          from: glp_address,
          to: ALICE,
          coins: Balance { coin: Coin::Serai, amount: Amount(0) }
        }),
        serai_abi::Event::Coins(serai_abi::coins::Event::Transfer {
          from: glp_address,
          to: ALICE,
          coins: Balance { coin: COIN.into(), amount: transfer.amount }
        }),
        serai_abi::Event::GenesisLiquidity(
          serai_abi::genesis_liquidity::Event::GenesisLiquidityRemoval {
            by: ALICE,
            genesis_liquidity: ExternalBalance { coin: COIN, amount: transfer.amount },
            sri_burnt,
            sri_yielded: Amount(0),
            external_coin_yielded: transfer.amount,
          }
        ),
      ]
    );
  });
}

#[test]
fn remove_genesis_liquidity_sans_upside() {
  new_test_ext().execute_with(|| {
    init_oraclized();

    // Even if the liquidity is now notably heavier with the external coin, this should be the same
    Coins::mint(
      serai_abi::dex::address(COIN),
      Balance { coin: Coin::External(COIN), amount: COIN_AMOUNT },
    )
    .unwrap();

    let transfer = ExternalBalance { coin: COIN, amount: Amount(1_000) };

    GenesisLiquidity::remove_genesis_liquidity(
      Some(ALICE).into(),
      transfer,
      Amount(0),
      transfer.amount,
    )
    .unwrap();

    let new_genesis_liquidity_supply = (COIN_AMOUNT - transfer.amount).unwrap();

    let sri_burnt = Amount(2_000 / 2);
    let new_serai_supply = (SRI_AMOUNT - sri_burnt).unwrap();

    let pool_address = serai_abi::dex::address(COIN);
    let glp_address = serai_abi::genesis_liquidity::address(COIN);

    assert_eq!(GenesisLiquidityTokens::supply(COIN), new_genesis_liquidity_supply);
    assert_eq!(GenesisLiquidityTokens::balance(ALICE, COIN), new_genesis_liquidity_supply);

    let corresponding_lp = Amount(1_500);
    let lp_removed = (LP_AMOUNT - LiquidityTokens::balance(glp_address, COIN)).unwrap();
    assert_eq!(lp_removed, corresponding_lp);
    // The liquidity necessary for the removal should have been burnt
    assert_eq!(
      LiquidityTokens::supply(COIN),
      (LP_AMOUNT - Amount(corresponding_lp.0 / 2)).unwrap()
    );
    // But the difference between what was available and what was required should become PoL
    assert_eq!(LiquidityTokens::balance(pool_address, COIN), Amount(corresponding_lp.0 / 2));

    assert_eq!(Coins::supply(Coin::Serai), new_serai_supply);
    assert_eq!(Coins::balance(ALICE, Coin::Serai), Amount(0));
    assert_eq!(Coins::balance(pool_address, Coin::Serai), new_serai_supply);

    assert_eq!(Coins::supply(COIN), Amount(2 * COIN_AMOUNT.0));
    assert_eq!(Coins::balance(ALICE, COIN), transfer.amount);
    assert_eq!(
      Coins::balance(pool_address, COIN),
      (Amount(2 * COIN_AMOUNT.0) - transfer.amount).unwrap()
    );
  });
}

#[test]
fn remove_genesis_liquidity_half_upside() {
  new_test_ext().execute_with(|| {
    init_oraclized();

    Coins::mint(
      serai_abi::dex::address(COIN),
      Balance { coin: Coin::External(COIN), amount: COIN_AMOUNT },
    )
    .unwrap();

    crate::EconomicSecurityAchieved::<Test>::set(Some(0));
    // As it's halfway through the trickle feed, they should get half the upside
    Timestamp::set_timestamp(u64::try_from(crate::GENESIS_TRICKLE_FEED / 2).unwrap());

    let transfer = ExternalBalance { coin: COIN, amount: Amount(1_000) };

    GenesisLiquidity::remove_genesis_liquidity(
      Some(ALICE).into(),
      transfer,
      Amount(0),
      transfer.amount,
    )
    .unwrap();

    let new_genesis_liquidity_supply = (COIN_AMOUNT - transfer.amount).unwrap();

    // The original amount, plus 50% of the upside, causes us to remove 75% of the liquidity
    let corresponding_sri = Amount((2_000 * 3) / 4);
    // But only 50% of the SRI upside will be yielded
    let yielded_sri = Amount(corresponding_sri.0 / 2);
    let sri_burnt = (corresponding_sri - yielded_sri).unwrap();
    let new_serai_supply = (SRI_AMOUNT - sri_burnt).unwrap();

    let pool_address = serai_abi::dex::address(COIN);
    let glp_address = serai_abi::genesis_liquidity::address(COIN);

    assert_eq!(GenesisLiquidityTokens::supply(COIN), new_genesis_liquidity_supply);
    assert_eq!(GenesisLiquidityTokens::balance(ALICE, COIN), new_genesis_liquidity_supply);

    let corresponding_lp = Amount(1_500);
    let lp_removed = (LP_AMOUNT - LiquidityTokens::balance(glp_address, COIN)).unwrap();
    assert_eq!(lp_removed, corresponding_lp);
    assert_eq!(
      LiquidityTokens::supply(COIN),
      (LP_AMOUNT - Amount((corresponding_lp.0 * 3) / 4)).unwrap()
    );
    assert_eq!(LiquidityTokens::balance(pool_address, COIN), Amount(corresponding_lp.0 / 4));

    assert_eq!(Coins::supply(Coin::Serai), new_serai_supply);
    assert_eq!(Coins::balance(ALICE, Coin::Serai), yielded_sri);
    assert_eq!(
      Coins::balance(pool_address, Coin::Serai),
      (new_serai_supply - yielded_sri).unwrap()
    );

    assert_eq!(Coins::supply(COIN), Amount(2 * COIN_AMOUNT.0));
    assert_eq!(Coins::balance(ALICE, COIN), Amount((transfer.amount.0 * 3) / 2));
    assert_eq!(
      Coins::balance(pool_address, COIN),
      (Amount(2 * COIN_AMOUNT.0) - Amount((transfer.amount.0 * 3) / 2)).unwrap()
    );
  });
}

#[test]
fn remove_genesis_liquidity_post_trickle() {
  new_test_ext().execute_with(|| {
    init_oraclized();

    Coins::mint(
      serai_abi::dex::address(COIN),
      Balance { coin: Coin::External(COIN), amount: COIN_AMOUNT },
    )
    .unwrap();

    crate::EconomicSecurityAchieved::<Test>::set(Some(0));
    Timestamp::set_timestamp(u64::try_from(crate::GENESIS_TRICKLE_FEED).unwrap() + 1);

    let transfer = ExternalBalance { coin: COIN, amount: Amount(1_000) };

    GenesisLiquidity::remove_genesis_liquidity(
      Some(ALICE).into(),
      transfer,
      Amount(0),
      transfer.amount,
    )
    .unwrap();

    let new_genesis_liquidity_supply = (COIN_AMOUNT - transfer.amount).unwrap();

    let corresponding_sri = Amount(2_000);
    let yielded_sri = corresponding_sri;
    let sri_burnt = Amount(0);
    let new_serai_supply = (SRI_AMOUNT - sri_burnt).unwrap();

    let pool_address = serai_abi::dex::address(COIN);
    let glp_address = serai_abi::genesis_liquidity::address(COIN);

    assert_eq!(GenesisLiquidityTokens::supply(COIN), new_genesis_liquidity_supply);
    assert_eq!(GenesisLiquidityTokens::balance(ALICE, COIN), new_genesis_liquidity_supply);

    let corresponding_lp = Amount(1_500);
    let lp_removed = (LP_AMOUNT - LiquidityTokens::balance(glp_address, COIN)).unwrap();
    assert_eq!(lp_removed, corresponding_lp);
    assert_eq!(LiquidityTokens::supply(COIN), (LP_AMOUNT - corresponding_lp).unwrap());
    assert_eq!(LiquidityTokens::balance(pool_address, COIN), Amount(0));

    assert_eq!(Coins::supply(Coin::Serai), new_serai_supply);
    assert_eq!(Coins::balance(ALICE, Coin::Serai), yielded_sri);
    assert_eq!(
      Coins::balance(pool_address, Coin::Serai),
      (new_serai_supply - yielded_sri).unwrap()
    );

    assert_eq!(Coins::supply(COIN), Amount(2 * COIN_AMOUNT.0));
    assert_eq!(Coins::balance(ALICE, COIN), Amount(transfer.amount.0 * 2));
    assert_eq!(
      Coins::balance(pool_address, COIN),
      (Amount(2 * COIN_AMOUNT.0) - Amount(transfer.amount.0 * 2)).unwrap()
    );
  });
}

#[test]
fn remove_genesis_liquidity_with_downside() {
  new_test_ext().execute_with(|| {
    init_oraclized();

    Coins::mint(serai_abi::dex::address(COIN), Balance { coin: Coin::Serai, amount: SRI_AMOUNT })
      .unwrap();
    // `disallowed_methods` is fine for this test
    #[expect(clippy::disallowed_methods)]
    Coins::burn_fn(
      serai_abi::dex::address(COIN),
      Balance { coin: Coin::External(COIN), amount: Amount(COIN_AMOUNT.0 / 4) },
    )
    .unwrap();

    let transfer = ExternalBalance { coin: COIN, amount: Amount(1_000) };

    let corresponding_sri = Amount(4_000);
    let expected_sri = Amount(1_333);

    GenesisLiquidity::remove_genesis_liquidity(
      Some(ALICE).into(),
      transfer,
      expected_sri,
      Amount(0),
    )
    .unwrap();

    let new_genesis_liquidity_supply = (COIN_AMOUNT - transfer.amount).unwrap();

    let sri_burnt = (corresponding_sri - expected_sri).unwrap();
    let new_serai_supply = (Amount(2 * SRI_AMOUNT.0) - sri_burnt).unwrap();

    let pool_address = serai_abi::dex::address(COIN);
    let glp_address = serai_abi::genesis_liquidity::address(COIN);

    assert_eq!(GenesisLiquidityTokens::supply(COIN), new_genesis_liquidity_supply);
    assert_eq!(GenesisLiquidityTokens::balance(ALICE, COIN), new_genesis_liquidity_supply);

    let corresponding_lp = Amount(1_500);
    let lp_removed = (LP_AMOUNT - LiquidityTokens::balance(glp_address, COIN)).unwrap();
    assert_eq!(lp_removed, corresponding_lp);
    assert_eq!(LiquidityTokens::supply(COIN), (LP_AMOUNT - corresponding_lp).unwrap());

    assert_eq!(Coins::supply(Coin::Serai), new_serai_supply);
    assert_eq!(Coins::balance(ALICE, Coin::Serai), expected_sri);
    assert_eq!(
      Coins::balance(pool_address, Coin::Serai),
      (new_serai_supply - expected_sri).unwrap()
    );

    assert_eq!(Coins::supply(COIN), Amount((COIN_AMOUNT.0 * 3) / 4));
    assert_eq!(Coins::balance(ALICE, COIN), Amount((transfer.amount.0 * 3) / 4));
    assert_eq!(
      Coins::balance(pool_address, COIN),
      (Amount((COIN_AMOUNT.0 * 3) / 4) - Amount((transfer.amount.0 * 3) / 4)).unwrap()
    );
  });
}
