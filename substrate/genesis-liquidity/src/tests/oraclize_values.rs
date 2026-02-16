use super::*;

#[test]
fn oraclize_values() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    let eve = SeraiAddress::from(Pair::generate().0.public());

    for (coin, amount) in [
      (ExternalCoin::Bitcoin, Amount(2 * 10u64.pow(ExternalCoin::Bitcoin.decimals()))),
      (ExternalCoin::Ether, Amount(2 * 10u64.pow(ExternalCoin::Ether.decimals()))),
      (ExternalCoin::Dai, Amount(3 * 10u64.pow(ExternalCoin::Dai.decimals()))),
      (ExternalCoin::Monero, Amount(4 * 10u64.pow(ExternalCoin::Monero.decimals()))),
    ] {
      let balance = ExternalBalance { coin, amount };
      Coins::mint(eve, balance.into()).unwrap();
      GenesisLiquidity::add_liquidity(eve, eve, balance).unwrap();
      assert_eq!(Coins::balance(eve, coin), Amount(0));
      assert_eq!(Coins::balance(serai_abi::genesis_liquidity::address(coin), coin), amount);
      assert_eq!(GenesisLiquidityTokens::balance(eve, coin), amount);
      assert_eq!(
        Core::events().last().unwrap().last().unwrap(),
        &borsh::to_vec(&serai_abi::Event::from(Event::GenesisLiquidityAdded {
          to: eve,
          genesis_liquidity: balance
        }))
        .unwrap()
      );
    }

    GenesisLiquidity::oraclize_values(
      None.into(),
      GenesisValues {
        ether: Amount(5 * 10u64.pow(ExternalCoin::Bitcoin.decimals())),
        dai: Amount(6 * 10u64.pow(ExternalCoin::Bitcoin.decimals())),
        monero: Amount(5 * 10u64.pow(ExternalCoin::Bitcoin.decimals())),
      },
      bitvec::vec::BitVec::<_, _>::new().try_into().unwrap(),
      serai_abi::primitives::crypto::RistrettoSignature([0; 64]),
    )
    .unwrap();

    for (coin, percent) in [
      (ExternalCoin::Bitcoin, 4),
      (ExternalCoin::Ether, 20),
      (ExternalCoin::Dai, 36),
      (ExternalCoin::Monero, 40),
    ] {
      assert_eq!(Coins::balance(serai_abi::dex::address(coin), coin), Coins::supply(coin));
      assert_eq!(
        Coins::balance(serai_abi::dex::address(coin), Coin::Serai),
        Amount(crate::GENESIS_SRI.0 * percent / 100)
      );
      let supply = LiquidityTokens::supply(coin);
      assert!(supply != Amount(0));
      assert_eq!(
        LiquidityTokens::balance(serai_abi::genesis_liquidity::address(coin), coin),
        supply
      );
    }
  });
}
