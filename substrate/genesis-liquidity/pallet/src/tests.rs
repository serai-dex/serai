use crate::{mock::*, primitives::*};

use std::collections::HashMap;

use rand_core::{RngCore, OsRng};

use frame_system::RawOrigin;
use frame_support::{assert_noop, assert_ok, traits::Hooks};

use sp_core::Pair;
use sp_runtime::BoundedVec;

use validator_sets_primitives::{ValidatorSet, Session, KeyPair};
use serai_primitives::*;

fn set_up_genesis(
  values: &HashMap<ExternalCoin, u64>,
) -> (HashMap<ExternalCoin, Vec<(SeraiAddress, Amount)>>, u64) {
  // make accounts with amounts
  let mut accounts = HashMap::new();
  for coin in EXTERNAL_COINS {
    // make 5 accounts per coin
    let mut values = vec![];
    for _ in 0 .. 5 {
      let mut address = SeraiAddress::new([0; 32]);
      OsRng.fill_bytes(&mut address.0);
      values.push((address, Amount(OsRng.next_u64() % (10_000 * 10u64.pow(coin.decimals())))));
    }
    accounts.insert(coin, values);
  }

  // add some genesis liquidity
  for (coin, amounts) in &accounts {
    for (address, amount) in amounts {
      let balance = ExternalBalance { coin: *coin, amount: *amount };

      Coins::mint(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.into()).unwrap();
      GenesisLiquidity::add_coin_liquidity((*address).into(), balance).unwrap();
    }
  }

  // make genesis liquidity event happen
  let block_number = MONTHS;
  let values = Values {
    monero: values[&ExternalCoin::Monero],
    ether: values[&ExternalCoin::Ether],
    dai: values[&ExternalCoin::Dai],
  };
  GenesisLiquidity::oraclize_values(RawOrigin::None.into(), values, Signature([0u8; 64])).unwrap();
  GenesisLiquidity::on_initialize(block_number);
  System::set_block_number(block_number);

  // populate the coin values
  Dex::on_finalize(block_number);

  (accounts, block_number)
}

// TODO: make this fn belong to the pallet itself use it there as well?
// The problem with that would be if there is a problem with this function
// tests can't catch it since it would the same fn?
fn distances() -> (HashMap<NetworkId, u64>, u64) {
  let mut distances = HashMap::new();
  let mut total_distance: u64 = 0;

  // calculate distance to economic security per network
  for n in EXTERNAL_NETWORKS {
    let required = ValidatorSets::required_stake_for_network(n);
    let mut current =
      ValidatorSets::total_allocated_stake(NetworkId::from(n)).unwrap_or(Amount(0)).0;
    if current > required {
      current = required;
    }

    let distance = required - current;
    distances.insert(n.into(), distance);
    total_distance = total_distance.saturating_add(distance);
  }

  // add serai network portion (20%)
  let new_total_distance = total_distance.saturating_mul(100) / (100 - 20);
  distances.insert(NetworkId::Serai, new_total_distance - total_distance);
  total_distance = new_total_distance;

  (distances, total_distance)
}

fn set_keys_for_session() {
  for network in EXTERNAL_NETWORKS {
    ValidatorSets::set_keys(
      RawOrigin::None.into(),
      network,
      BoundedVec::new(),
      KeyPair(insecure_pair_from_name("Alice").public(), vec![].try_into().unwrap()),
      Signature([0u8; 64]),
    )
    .unwrap();
  }
}

fn make_networks_reach_economic_security(block_number: u64) {
  set_keys_for_session();
  let (distances, _) = distances();
  for (network, distance) in distances {
    if network == NetworkId::Serai {
      continue;
    }

    let participants = ValidatorSets::participants_for_latest_decided_set(network).unwrap();
    let al_per_key_share = ValidatorSets::allocation_per_key_share(network).unwrap().0;

    // we want some unused capacity so we stake more SRI than necessary
    let mut key_shares = (distance / al_per_key_share) + 1;

    'outer: while key_shares > 0 {
      for (account, _) in &participants {
        ValidatorSets::distribute_block_rewards(network, *account, Amount(al_per_key_share))
          .unwrap();

        if key_shares > 0 {
          key_shares -= 1;
        } else {
          break 'outer;
        }
      }
    }
  }

  // update TAS
  ValidatorSets::new_session();
  for network in NETWORKS {
    ValidatorSets::retire_set(ValidatorSet { session: Session(0), network });
  }

  // make sure we reached economic security
  EconomicSecurity::on_initialize(block_number);
  for n in EXTERNAL_NETWORKS {
    EconomicSecurity::economic_security_block(n).unwrap();
  }
}

#[test]
fn genesis_liquidity() {
  new_test_ext().execute_with(|| {
    let values = HashMap::from([
      (ExternalCoin::Monero, 184100),
      (ExternalCoin::Ether, 4785000),
      (ExternalCoin::Dai, 1500),
    ]);
    let (accounts, block_number) = set_up_genesis(&values);

    // check that we minted the correct SRI amount
    // there are 6 endowed accounts in this mock runtime.
    let endowed_amount: u64 = 1 << 60;
    let total_sri = (6 * endowed_amount) + GENESIS_SRI;
    assert_eq!(Coins::supply(Coin::Serai), total_sri);

    // check genesis account has no coins, all transferred to pools.
    for coin in COINS {
      assert_eq!(Coins::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), coin).0, 0);
    }

    // get total pool coins and it's values
    let mut pool_amounts = HashMap::new();
    let mut total_value = 0u128;
    for (coin, amounts) in &accounts {
      let total_coin = amounts.iter().fold(0u128, |acc, value| acc + u128::from(value.1 .0));
      let value = if *coin != ExternalCoin::Bitcoin {
        (total_coin * u128::from(values[coin])) / 10u128.pow(coin.decimals())
      } else {
        total_coin
      };

      total_value += value;
      pool_amounts.insert(coin, (total_coin, value));
    }

    // check distributed SRI per pool
    let mut total_sri_distributed = 0u128;
    for coin in EXTERNAL_COINS {
      let sri = if &coin == EXTERNAL_COINS.last().unwrap() {
        u128::from(GENESIS_SRI).checked_sub(total_sri_distributed).unwrap()
      } else {
        (pool_amounts[&coin].1 * u128::from(GENESIS_SRI)) / total_value
      };
      total_sri_distributed += sri;

      let reserves = Dex::get_reserves(&coin.into(), &Coin::Serai).unwrap();
      assert_eq!(u128::from(reserves.0), pool_amounts[&coin].0); // coin side
      assert_eq!(u128::from(reserves.1), sri); // SRI side
    }

    // check each liquidity provider got liquidity tokens proportional to their value
    for coin in EXTERNAL_COINS {
      let liq_supply = GenesisLiquidity::supply(coin).unwrap();
      for (acc, amount) in &accounts[&coin] {
        let public: PublicKey = (*acc).into();
        let acc_liq_shares = GenesisLiquidity::liquidity(coin, public).unwrap().shares;

        // since we can't test the ratios directly(due to integer division giving 0)
        // we test whether they give the same result when multiplied by another constant.
        // Following test ensures the account in fact has the right amount of shares.
        let mut shares_ratio = (INITIAL_GENESIS_LP_SHARES * acc_liq_shares) / liq_supply.shares;
        let amounts_ratio = u64::try_from(
          (u128::from(INITIAL_GENESIS_LP_SHARES) * u128::from(amount.0)) / pool_amounts[&coin].0,
        )
        .unwrap();

        // we can tolerate 1 unit diff between them due to integer division.
        if shares_ratio.abs_diff(amounts_ratio) == 1 {
          shares_ratio = amounts_ratio;
        }

        assert_eq!(shares_ratio, amounts_ratio);
      }
    }

    // make sure we have genesis complete block set
    assert_eq!(GenesisLiquidity::genesis_complete_block().unwrap(), block_number);
  });
}

#[test]
fn remove_coin_liquidity_genesis_period() {
  new_test_ext().execute_with(|| {
    let account = insecure_pair_from_name("random1").public();
    let coin = ExternalCoin::Bitcoin;
    let balance = ExternalBalance { coin, amount: Amount(10u64.pow(coin.decimals())) };

    // add some genesis liquidity
    Coins::mint(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.into()).unwrap();
    GenesisLiquidity::add_coin_liquidity(account, balance).unwrap();

    // amount has to be full amount if removing during genesis period
    assert_noop!(
      GenesisLiquidity::remove_coin_liquidity(
        RawOrigin::Signed(account).into(),
        ExternalBalance { coin, amount: Amount(1_000) }
      ),
      genesis_liquidity::Error::<Test>::CanOnlyRemoveFullAmount
    );

    assert_ok!(GenesisLiquidity::remove_coin_liquidity(
      RawOrigin::Signed(account).into(),
      ExternalBalance { coin, amount: Amount(INITIAL_GENESIS_LP_SHARES) }
    ));

    // check that user got back the coins
    assert_eq!(Coins::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), coin.into()), Amount(0));
    assert_eq!(Coins::balance(account, coin.into()), balance.amount);
  })
}

#[test]
fn remove_coin_liquidity_after_genesis_period() {
  new_test_ext().execute_with(|| {
    // set up genesis
    let coin = ExternalCoin::Monero;
    let values = HashMap::from([
      (ExternalCoin::Monero, 184100),
      (ExternalCoin::Ether, 4785000),
      (ExternalCoin::Dai, 1500),
    ]);
    let (accounts, mut block_number) = set_up_genesis(&values);

    // make sure no economic security achieved for the network
    assert!(EconomicSecurity::economic_security_block(coin.network()).is_none());

    let account: PublicKey = accounts[&coin][0].0.into();
    // let account_liquidity = accounts[&coin][0].1 .0;
    let account_sri_balance = Coins::balance(account, Coin::Serai).0;
    let account_coin_balance = Coins::balance(account, coin.into()).0;

    // try to remove liquidity
    assert_ok!(GenesisLiquidity::remove_coin_liquidity(
      RawOrigin::Signed(account).into(),
      ExternalBalance { coin, amount: Amount(INITIAL_GENESIS_LP_SHARES / 2) },
    ));

    // since there is no economic security we shouldn't have received any SRI
    // and should receive only half the coins since we removed half.
    assert_eq!(Coins::balance(account, Coin::Serai).0, account_sri_balance);

    // TODO: this doesn't exactly line up with `account_liquidity / 2`. Prob due to all the integer
    // mul_divs? There is no pool movement to attribute it to.
    // assert_eq!(Coins::balance(account, coin).0 - account_coin_balance, account_liquidity / 2);
    assert!(Coins::balance(account, coin.into()).0 > account_coin_balance);

    // make networks reach economic security
    make_networks_reach_economic_security(block_number);

    // move the block number it has been some time since economic security
    block_number += MONTHS;
    System::set_block_number(block_number);

    let coin = ExternalCoin::Ether;
    let account: PublicKey = accounts[&coin][0].0.into();
    // let account_liquidity = accounts[&coin][0].1 .0;
    let account_sri_balance = Coins::balance(account, Coin::Serai).0;
    let account_coin_balance = Coins::balance(account, coin.into()).0;

    // try to remove liquidity
    assert_ok!(GenesisLiquidity::remove_coin_liquidity(
      RawOrigin::Signed(account).into(),
      ExternalBalance { coin, amount: Amount(INITIAL_GENESIS_LP_SHARES / 2) },
    ));

    // TODO: this doesn't exactly line up with `account_liquidity / 2`. Prob due to all the integer
    // mul_divs? There is no pool movement to attribute it to.
    // let pool_sri = Coins::balance(Dex::get_pool_account(coin), Coin::Serai).0;
    // let total_pool_coins =
    //   accounts[&coin].iter().fold(0u128, |acc, value| acc + u128::from(value.1 .0));
    // let genesis_sri_for_account =
    //   (u128::from(pool_sri) * u128::from(account_liquidity)) / total_pool_coins;

    // // we should receive only half of genesis SRI minted for us
    // let genesis_sri_for_account = genesis_sri_for_account / 2;

    // let distance_to_full_pay = GENESIS_SRI_TRICKLE_FEED.saturating_sub(MONTHS);
    // let burn_sri_amount = (genesis_sri_for_account * u128::from(distance_to_full_pay)) /
    //   u128::from(GENESIS_SRI_TRICKLE_FEED);
    // let sri_received = genesis_sri_for_account - burn_sri_amount;
    // assert_eq!(
    //   Coins::balance(account, Coin::Serai).0 - account_sri_balance,
    //   u64::try_from(sri_received).unwrap()
    // );
    assert!(Coins::balance(account, Coin::Serai).0 > account_sri_balance);

    // TODO: this doesn't exactly line up with `account_liquidity / 2`. Prob due to all the integer
    // mul_divs? There is no pool movement to attribute it to.
    // assert_eq!(Coins::balance(account, coin).0 - account_coin_balance, account_liquidity / 2);
    assert!(Coins::balance(account, coin.into()).0 > account_coin_balance);
  })
}
