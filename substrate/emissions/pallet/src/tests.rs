use crate::{mock::*, primitives::*};

use rand_core::{RngCore, OsRng};

use sp_core::{sr25519::Signature, Pair};
use sp_std::{vec, collections::btree_map::BTreeMap};
use sp_runtime::BoundedVec;

use frame_system::RawOrigin;
use frame_support::traits::{Hooks, Get};

use genesis_liquidity_pallet::{
  Pallet as GenesisLiquidity,
  primitives::{Values, GENESIS_LIQUIDITY_ACCOUNT},
};
use validator_sets_pallet::{Pallet as ValidatorSets, primitives::Session};
use coins_pallet::Pallet as Coins;
use dex_pallet::Pallet as Dex;

use serai_primitives::*;
use validator_sets_primitives::{KeyPair, ValidatorSet};

fn set_up_genesis() -> u64 {
  // add some genesis liquidity
  for coin in COINS {
    if coin == Coin::Serai {
      continue;
    }

    let mut address = SeraiAddress::new([0; 32]);
    OsRng.fill_bytes(&mut address.0);
    let balance = Balance { coin, amount: Amount(OsRng.next_u64() % 10u64.pow(coin.decimals())) };

    Coins::<Test>::mint(GENESIS_LIQUIDITY_ACCOUNT.into(), balance).unwrap();
    GenesisLiquidity::<Test>::add_coin_liquidity(address.into(), balance).unwrap();
  }

  // make genesis liquidity event happen
  let block_number = MONTHS;
  let values = Values { monero: 184100, ether: 4785000, dai: 1500 };
  GenesisLiquidity::<Test>::oraclize_values(RawOrigin::None.into(), values, Signature([0u8; 64]))
    .unwrap();
  <GenesisLiquidity<Test> as Hooks<BlockNumber>>::on_initialize(block_number);
  System::set_block_number(block_number);

  // populate the coin values
  <Dex<Test> as Hooks<BlockNumber>>::on_finalize(block_number);

  block_number
}

// TODO: make this fn belong to the pallet itself use it there as well?
// The problem with that would be if there is a problem with this function
// tests can't catch it since it would the same fn?
fn distances() -> (BTreeMap<NetworkId, u64>, u64) {
  let mut distances = BTreeMap::new();
  let mut total_distance: u64 = 0;

  // calculate distance to economic security per network
  for n in NETWORKS {
    if n == NetworkId::Serai {
      continue;
    }

    let required = ValidatorSets::<Test>::required_stake_for_network(n);
    let mut current = ValidatorSets::<Test>::total_allocated_stake(n).unwrap_or(Amount(0)).0;
    if current > required {
      current = required;
    }

    let distance = required - current;
    distances.insert(n, distance);
    total_distance = total_distance.saturating_add(distance);
  }

  // add serai network portion (20%)
  let new_total_distance =
    total_distance.saturating_mul(100) / (100 - SERAI_VALIDATORS_DESIRED_PERCENTAGE);
  distances.insert(NetworkId::Serai, new_total_distance - total_distance);
  total_distance = new_total_distance;

  (distances, total_distance)
}

fn set_keys_for_session() {
  for n in NETWORKS {
    if n == NetworkId::Serai {
      continue;
    }

    ValidatorSets::<Test>::set_keys(
      RawOrigin::None.into(),
      n,
      BoundedVec::new(),
      KeyPair(insecure_pair_from_name("Alice").public(), vec![].try_into().unwrap()),
      Signature([0u8; 64]),
    )
    .unwrap();
  }
}

#[test]
fn check_pre_ec_security_initial_period_emissions() {
  new_test_ext().execute_with(|| {
    // set up genesis liquidity
    let mut block_number = set_up_genesis();

    for _ in 0 .. 5 {
      // set session keys. we need this here before reading the current stakes for session 0.
      // We need it for other sessions to be able to retire the set.
      set_keys_for_session();

      // get current stakes
      let mut current_stake = BTreeMap::new();
      for n in NETWORKS {
        current_stake.insert(n, ValidatorSets::<Test>::total_allocated_stake(n).unwrap().0);
      }

      // trigger rewards distribution for the past session
      ValidatorSets::<Test>::new_session();
      <Emissions as Hooks<BlockNumber>>::on_initialize(block_number + 1);

      // calculate the total reward for this epoch
      let (distances, total_distance) = distances();
      let session = ValidatorSets::<Test>::session(NetworkId::Serai).unwrap_or(Session(0));
      let block_count = ValidatorSets::<Test>::session_begin_block(NetworkId::Serai, session) -
        ValidatorSets::<Test>::session_begin_block(NetworkId::Serai, Session(session.0 - 1));
      let reward_this_epoch = block_count * INITIAL_REWARD_PER_BLOCK;

      let reward_per_network = distances
        .into_iter()
        .map(|(n, distance)| {
          // calculate how much each network gets based on distance to ec-security
          let reward = u64::try_from(
            u128::from(reward_this_epoch).saturating_mul(u128::from(distance)) /
              u128::from(total_distance),
          )
          .unwrap();
          (n, reward)
        })
        .collect::<BTreeMap<NetworkId, u64>>();

      for (n, reward) in reward_per_network {
        ValidatorSets::<Test>::retire_set(ValidatorSet {
          session: Session(session.0 - 1),
          network: n,
        });

        // all validator rewards should automatically be staked
        assert_eq!(
          ValidatorSets::<Test>::total_allocated_stake(n).unwrap().0,
          *current_stake.get(&n).unwrap() + reward
        );
      }

      block_number += <<Test as pallet_babe::Config>::EpochDuration as Get<u64>>::get();
      System::set_block_number(block_number);
    }
  });
}

#[test]
fn check_pre_ec_security_emissions() {
  new_test_ext().execute_with(|| {
    // set up genesis liquidity
    let mut block_number = set_up_genesis();

    // move the block number out of initial period which is 2 more months
    block_number += 2 * MONTHS;
    System::set_block_number(block_number);

    for _ in 0 .. 5 {
      // set session keys. we need this here before reading the current stakes for session 0.
      // We need it for other sessions to be able to retire the set.
      set_keys_for_session();

      // get current stakes
      let mut current_stake = BTreeMap::new();
      for n in NETWORKS {
        current_stake.insert(n, ValidatorSets::<Test>::total_allocated_stake(n).unwrap().0);
      }

      // trigger rewards distribution for the past session
      ValidatorSets::<Test>::new_session();
      <Emissions as Hooks<BlockNumber>>::on_initialize(block_number + 1);

      // calculate the total reward for this epoch
      let (distances, total_distance) = distances();
      let session = ValidatorSets::<Test>::session(NetworkId::Serai).unwrap_or(Session(0));
      let block_count = ValidatorSets::<Test>::session_begin_block(NetworkId::Serai, session) -
        ValidatorSets::<Test>::session_begin_block(NetworkId::Serai, Session(session.0 - 1));
      let reward_this_epoch = block_count * (total_distance / (SECURE_BY - block_number));

      let reward_per_network = distances
        .into_iter()
        .map(|(n, distance)| {
          // calculate how much each network gets based on distance to ec-security
          let reward = u64::try_from(
            u128::from(reward_this_epoch).saturating_mul(u128::from(distance)) /
              u128::from(total_distance),
          )
          .unwrap();
          (n, reward)
        })
        .collect::<BTreeMap<NetworkId, u64>>();

      for (n, reward) in reward_per_network {
        ValidatorSets::<Test>::retire_set(ValidatorSet {
          session: Session(session.0 - 1),
          network: n,
        });

        // all validator rewards should automatically be staked
        assert_eq!(
          ValidatorSets::<Test>::total_allocated_stake(n).unwrap().0,
          *current_stake.get(&n).unwrap() + reward
        );
      }

      block_number += <<Test as pallet_babe::Config>::EpochDuration as Get<u64>>::get();
      System::set_block_number(block_number);
    }
  });
}
