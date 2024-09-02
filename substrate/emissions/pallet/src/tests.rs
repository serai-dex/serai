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
use economic_security::Pallet as EconomicSecurity;

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
    let balance =
      Balance { coin, amount: Amount(OsRng.next_u64() % (10_000 * 10u64.pow(coin.decimals()))) };

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

fn make_fake_swap_volume() {
  let acc = insecure_pair_from_name("random").public();
  for _ in 0 .. 10 {
    let path_len = (OsRng.next_u32() % 2) + 2;

    let coins = &COINS[1 ..];
    let path = if path_len == 2 {
      let coin = coins[(OsRng.next_u32() as usize) % coins.len()];
      let in_or_out = (OsRng.next_u32() % 2) == 0;
      if in_or_out {
        vec![coin, Coin::Serai]
      } else {
        vec![Coin::Serai, coin]
      }
    } else {
      let in_coin = coins[(OsRng.next_u32() as usize) % coins.len()];
      let coins_without_in_coin = coins.iter().filter(|&c| *c != in_coin).collect::<Vec<_>>();
      let out_coin =
        coins_without_in_coin[(OsRng.next_u32() as usize) % coins_without_in_coin.len()];
      vec![in_coin, Coin::Serai, *out_coin]
    };

    let one_in_coin = 10u64.pow(path[0].decimals());
    Coins::<Test>::mint(acc, Balance { coin: path[0], amount: Amount(2 * one_in_coin) }).unwrap();
    let amount_in = OsRng.next_u64() % (one_in_coin);

    Dex::<Test>::swap_exact_tokens_for_tokens(
      RawOrigin::Signed(acc).into(),
      path.try_into().unwrap(),
      amount_in,
      1,
      acc,
    )
    .unwrap();
  }
}

fn get_session_swap_volumes(
  last_swap_volume: &mut BTreeMap<Coin, u64>,
) -> (BTreeMap<Coin, u64>, BTreeMap<NetworkId, u64>, u64) {
  let mut volume_per_coin: BTreeMap<Coin, u64> = BTreeMap::new();
  for c in COINS {
    // this should return 0 for SRI and so it shouldn't affect the total volume.
    let current_volume = Dex::<Test>::swap_volume(c).unwrap_or(0);
    let last_volume = last_swap_volume.get(&c).unwrap_or(&0);
    let vol_this_epoch = current_volume.saturating_sub(*last_volume);

    // update the current volume
    last_swap_volume.insert(c, current_volume);
    volume_per_coin.insert(c, vol_this_epoch);
  }

  // aggregate per network
  let mut total_volume = 0u64;
  let mut volume_per_network: BTreeMap<NetworkId, u64> = BTreeMap::new();
  for (c, vol) in &volume_per_coin {
    volume_per_network.insert(
      c.network(),
      (*volume_per_network.get(&c.network()).unwrap_or(&0)).saturating_add(*vol),
    );
    total_volume = total_volume.saturating_add(*vol);
  }

  (volume_per_coin, volume_per_network, total_volume)
}

fn get_pool_vs_validator_rewards(n: NetworkId, reward: u64) -> (u64, u64) {
  if n == NetworkId::Serai {
    (reward, 0)
  } else {
    // calculate pool vs validator share
    let capacity = ValidatorSets::<Test>::total_allocated_stake(n).unwrap_or(Amount(0)).0;
    let required = ValidatorSets::<Test>::required_stake_for_network(n);
    let unused_capacity = capacity.saturating_sub(required);

    let distribution = unused_capacity.saturating_mul(ACCURACY_MULTIPLIER) / capacity;
    let total = DESIRED_DISTRIBUTION.saturating_add(distribution);

    let validators_reward = DESIRED_DISTRIBUTION.saturating_mul(reward) / total;
    let network_pool_reward = reward.saturating_sub(validators_reward);
    (validators_reward, network_pool_reward)
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

    // make a fresh session
    set_keys_for_session();
    ValidatorSets::<Test>::new_session();
    for network in NETWORKS {
      ValidatorSets::<Test>::retire_set(ValidatorSet { session: Session(0), network });
    }

    // move the block for the next session
    block_number += <<Test as pallet_babe::Config>::EpochDuration as Get<u64>>::get();
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

#[test]
fn check_post_ec_security_emissions() {
  new_test_ext().execute_with(|| {
    // set up genesis liquidity
    let mut block_number = set_up_genesis();

    // make all networks reach economic security
    set_keys_for_session();
    let (distances, _) = distances();
    for (network, distance) in distances {
      if network == NetworkId::Serai {
        continue;
      }

      let participants =
        ValidatorSets::<Test>::participants_for_latest_decided_set(network).unwrap();
      let al_per_key_share = ValidatorSets::<Test>::allocation_per_key_share(network).unwrap().0;

      // we want some unused capacity so we stake more SRI than necessary
      let mut key_shares = (distance / al_per_key_share) + 10;

      'outer: while key_shares > 0 {
        for (account, _) in &participants {
          ValidatorSets::<Test>::distribute_block_rewards(
            network,
            *account,
            Amount(al_per_key_share),
          )
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
    ValidatorSets::<Test>::new_session();
    for network in NETWORKS {
      ValidatorSets::<Test>::retire_set(ValidatorSet { session: Session(0), network });
    }

    // make sure we reached economic security
    <EconomicSecurity<Test> as Hooks<BlockNumber>>::on_initialize(block_number);
    for n in NETWORKS.iter().filter(|&n| *n != NetworkId::Serai).collect::<Vec<_>>() {
      EconomicSecurity::<Test>::economic_security_block(*n).unwrap();
    }

    // move the block number for the next session
    block_number += <<Test as pallet_babe::Config>::EpochDuration as Get<u64>>::get();
    System::set_block_number(block_number);

    let mut last_swap_volume = BTreeMap::new();
    for _ in 0 .. 5 {
      set_keys_for_session();

      // make some fake swap volume
      make_fake_swap_volume();
      let (vpc, vpn, total_volume) = get_session_swap_volumes(&mut last_swap_volume);

      // get current stakes & each pool SRI amounts
      let mut current_stake = BTreeMap::new();
      let mut current_pool_coins = BTreeMap::new();
      for n in NETWORKS {
        current_stake.insert(n, ValidatorSets::<Test>::total_allocated_stake(n).unwrap().0);

        for c in n.coins() {
          let acc = Dex::<Test>::get_pool_account(*c);
          current_pool_coins.insert(c, Coins::<Test>::balance(acc, Coin::Serai).0);
        }
      }

      // trigger rewards distribution for the past session
      ValidatorSets::<Test>::new_session();
      <Emissions as Hooks<BlockNumber>>::on_initialize(block_number + 1);

      // calculate the total reward for this epoch
      let session = ValidatorSets::<Test>::session(NetworkId::Serai).unwrap_or(Session(0));
      let block_count = ValidatorSets::<Test>::session_begin_block(NetworkId::Serai, session) -
        ValidatorSets::<Test>::session_begin_block(NetworkId::Serai, Session(session.0 - 1));
      let reward_this_epoch = block_count * REWARD_PER_BLOCK;

      let reward_per_network = vpn
        .iter()
        .map(|(n, volume)| {
          let reward = if *n == NetworkId::Serai {
            reward_this_epoch / 5
          } else {
            let reward = reward_this_epoch - (reward_this_epoch / 5);
            // TODO: It is highly unlikely but what to do in case of 0 total volume?
            if total_volume != 0 {
              u64::try_from(
                u128::from(reward).saturating_mul(u128::from(*volume)) / u128::from(total_volume),
              )
              .unwrap()
            } else {
              0
            }
          };
          (*n, reward)
        })
        .collect::<BTreeMap<NetworkId, u64>>();

      for (n, reward) in reward_per_network {
        let (validator_rewards, network_pool_rewards) = get_pool_vs_validator_rewards(n, reward);
        ValidatorSets::<Test>::retire_set(ValidatorSet {
          session: Session(session.0 - 1),
          network: n,
        });

        // all validator rewards should automatically be staked
        assert_eq!(
          ValidatorSets::<Test>::total_allocated_stake(n).unwrap().0,
          *current_stake.get(&n).unwrap() + validator_rewards
        );

        // all pool rewards should be available in the pool account
        if network_pool_rewards != 0 {
          for c in n.coins() {
            let pool_reward = u64::try_from(
              u128::from(network_pool_rewards).saturating_mul(u128::from(vpc[c])) /
                u128::from(vpn[&n]),
            )
            .unwrap();

            let acc = Dex::<Test>::get_pool_account(*c);
            assert_eq!(
              Coins::<Test>::balance(acc, Coin::Serai).0,
              current_pool_coins[&c] + pool_reward
            )
          }
        }
      }

      block_number += <<Test as pallet_babe::Config>::EpochDuration as Get<u64>>::get();
      System::set_block_number(block_number);
    }
  });
}
