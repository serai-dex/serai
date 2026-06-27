use super::*;

const TEST_ID: &[u8] = b"oraclize_values";

#[test]
fn oraclize_values() {
  new_test_ext().execute_with(|| {
    sp_io::storage::set(TEST_ID_STORAGE, TEST_ID);

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

    let mut total_required_stake = crate::GENESIS_SRI.0 * 3 / 2;
    total_required_stake += total_required_stake / 5;
    // This is hard-coded to the length of the vector within the test environment's configuration
    let genesis_key_shares = 4u16;
    let target_key_shares = (2 * genesis_key_shares) + 1;

    let allocation_per_key_share =
      |required_stake: Amount| Amount(required_stake.0.div_ceil(u64::from(target_key_shares)));

    let mut percent_by_network = HashMap::new();
    for (coin, percent) in [
      (ExternalCoin::Bitcoin, 4),
      (ExternalCoin::Ether, 20),
      (ExternalCoin::Dai, 36),
      (ExternalCoin::Monero, 40),
    ] {
      assert_eq!(Coins::balance(serai_abi::dex::address(coin), coin), Coins::supply(coin));
      assert_eq!(
        Coins::balance(serai_abi::dex::address(coin), Coin::Serai),
        Amount((crate::GENESIS_SRI.0 * percent) / 100)
      );
      let supply = LiquidityTokens::supply(coin);
      assert_ne!(supply, Amount(0));
      assert_eq!(
        LiquidityTokens::balance(serai_abi::genesis_liquidity::address(coin), coin),
        supply
      );
      let sum_percent = percent_by_network.get(&coin.network()).copied().unwrap_or(0) + percent;
      percent_by_network.insert(coin.network(), sum_percent);
    }

    let set_allocation_per_key_share = SET_ALLOCATION_PER_KEY_SHARE.lock().unwrap();
    for (network, percent) in percent_by_network {
      assert_eq!(
        set_allocation_per_key_share[&(Some(TEST_ID.to_vec()), NetworkId::from(network))],
        allocation_per_key_share(Amount((total_required_stake * percent) / 100))
      );
    }

    assert_eq!(
      set_allocation_per_key_share[&(Some(TEST_ID.to_vec()), NetworkId::Serai)],
      // If it's 25% of the total required, it's 25% of the resulting 125%, or 20% as desired
      allocation_per_key_share(Amount((total_required_stake * 25) / 100))
    );
  });
}
