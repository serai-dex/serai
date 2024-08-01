use std::{time::Duration, collections::HashMap};
use rand_core::{RngCore, OsRng};

use serai_client::TemporalSerai;

use serai_abi::{
  emissions::primitives::{INITIAL_REWARD_PER_BLOCK, SECURE_BY},
  in_instructions::primitives::Batch,
  primitives::{
    BlockHash, Coin, COINS, FAST_EPOCH_DURATION, FAST_EPOCH_INITIAL_PERIOD, NETWORKS,
    TARGET_BLOCK_TIME,
  },
  validator_sets::primitives::Session,
};

use serai_client::{
  primitives::{Amount, NetworkId, Balance},
  Serai,
};

mod common;
use common::{genesis_liquidity::set_up_genesis, in_instructions::provide_batch};

serai_test_fast_epoch!(
  emissions: (|serai: Serai| async move {
    test_emissions(serai).await;
  })
);

async fn send_batches(serai: &Serai, ids: &mut HashMap<NetworkId, u32>) {
  for network in NETWORKS {
    if network != NetworkId::Serai {
      // set up batch id
      ids
        .entry(network)
        .and_modify(|v| {
          *v += 1;
        })
        .or_insert(0);

      // set up block hash
      let mut block = BlockHash([0; 32]);
      OsRng.fill_bytes(&mut block.0);

      provide_batch(serai, Batch { network, id: ids[&network], block, instructions: vec![] }).await;
    }
  }
}

async fn test_emissions(serai: Serai) {
  // set up the genesis
  let coins = COINS.into_iter().filter(|c| *c != Coin::native()).collect::<Vec<_>>();
  let values = HashMap::from([(Coin::Monero, 184100), (Coin::Ether, 4785000), (Coin::Dai, 1500)]);
  let (_, mut batch_ids) = set_up_genesis(&serai, &coins, &values).await;

  // wait until genesis is complete
  while !serai
    .as_of_latest_finalized_block()
    .await
    .unwrap()
    .genesis_liquidity()
    .genesis_complete()
    .await
    .unwrap()
  {
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  let genesis_complete_block = serai.latest_finalized_block().await.unwrap().number();

  for _ in 0 .. 3 {
    // get current stakes
    let mut current_stake = HashMap::new();
    for n in NETWORKS {
      // TODO: investigate why serai network TAS isn't visible at session 0.
      let stake = serai
        .as_of_latest_finalized_block()
        .await
        .unwrap()
        .validator_sets()
        .total_allocated_stake(n)
        .await
        .unwrap()
        .unwrap_or(Amount(0))
        .0;
      current_stake.insert(n, stake);
    }

    // wait for a session change
    let current_session = wait_for_session_change(&serai).await;

    // get last block
    let last_block = serai.latest_finalized_block().await.unwrap();
    let serai_latest = serai.as_of(last_block.hash());
    let change_block_number = last_block.number();

    // get distances to ec security & block count of the previous session
    let (distances, total_distance) = get_distances(&serai_latest, &current_stake).await;
    let block_count = get_session_blocks(&serai_latest, current_session - 1).await;

    // calculate how much reward in this session
    let reward_this_epoch =
      if change_block_number < (genesis_complete_block + FAST_EPOCH_INITIAL_PERIOD) {
        block_count * INITIAL_REWARD_PER_BLOCK
      } else {
        let blocks_until = SECURE_BY - change_block_number;
        let block_reward = total_distance / blocks_until;
        block_count * block_reward
      };

    let reward_per_network = distances
      .into_iter()
      .map(|(n, distance)| {
        let reward = u64::try_from(
          u128::from(reward_this_epoch).saturating_mul(u128::from(distance)) /
            u128::from(total_distance),
        )
        .unwrap();
        (n, reward)
      })
      .collect::<HashMap<NetworkId, u64>>();

    // retire the prev-set so that TotalAllocatedStake updated.
    send_batches(&serai, &mut batch_ids).await;

    for (n, reward) in reward_per_network {
      let stake = serai
        .as_of_latest_finalized_block()
        .await
        .unwrap()
        .validator_sets()
        .total_allocated_stake(n)
        .await
        .unwrap()
        .unwrap_or(Amount(0))
        .0;

      // all reward should automatically staked for the network since we are in initial period.
      assert_eq!(stake, *current_stake.get(&n).unwrap() + reward);
    }

    // TODO: check stake per address?
    // TODO: check post ec security era
  }
}

/// Returns the required stake in terms SRI for a given `Balance`.
async fn required_stake(serai: &TemporalSerai<'_>, balance: Balance) -> u64 {
  // This is inclusive to an increase in accuracy
  let sri_per_coin = serai.dex().oracle_value(balance.coin).await.unwrap().unwrap_or(Amount(0));

  // See dex-pallet for the reasoning on these
  let coin_decimals = balance.coin.decimals().max(5);
  let accuracy_increase = u128::from(10u64.pow(coin_decimals));

  let total_coin_value =
    u64::try_from(u128::from(balance.amount.0) * u128::from(sri_per_coin.0) / accuracy_increase)
      .unwrap_or(u64::MAX);

  // required stake formula (COIN_VALUE * 1.5) + margin(20%)
  let required_stake = total_coin_value.saturating_mul(3).saturating_div(2);
  required_stake.saturating_add(total_coin_value.saturating_div(5))
}

async fn wait_for_session_change(serai: &Serai) -> u32 {
  let current_session = serai
    .as_of_latest_finalized_block()
    .await
    .unwrap()
    .validator_sets()
    .session(NetworkId::Serai)
    .await
    .unwrap()
    .unwrap()
    .0;
  let next_session = current_session + 1;

  // lets wait double the epoch time.
  tokio::time::timeout(
    tokio::time::Duration::from_secs(FAST_EPOCH_DURATION * TARGET_BLOCK_TIME * 2),
    async {
      while serai
        .as_of_latest_finalized_block()
        .await
        .unwrap()
        .validator_sets()
        .session(NetworkId::Serai)
        .await
        .unwrap()
        .unwrap()
        .0 <
        next_session
      {
        tokio::time::sleep(Duration::from_secs(6)).await;
      }
    },
  )
  .await
  .unwrap();

  next_session
}

async fn get_distances(
  serai: &TemporalSerai<'_>,
  current_stake: &HashMap<NetworkId, u64>,
) -> (HashMap<NetworkId, u64>, u64) {
  // we should be in the initial period, so calculate how much each network supposedly get..
  // we can check the supply to see how much coin hence liability we have.
  let mut distances: HashMap<NetworkId, u64> = HashMap::new();
  let mut total_distance = 0;
  for n in NETWORKS {
    if n == NetworkId::Serai {
      continue;
    }

    let mut required = 0;
    for c in n.coins() {
      let amount = serai.coins().coin_supply(*c).await.unwrap();
      required += required_stake(serai, Balance { coin: *c, amount }).await;
    }

    let mut current = *current_stake.get(&n).unwrap();
    if current > required {
      current = required;
    }

    let distance = required - current;
    total_distance += distance;

    distances.insert(n, distance);
  }

  // add serai network portion(20%)
  let new_total_distance = total_distance.saturating_mul(10) / 8;
  distances.insert(NetworkId::Serai, new_total_distance - total_distance);
  total_distance = new_total_distance;

  (distances, total_distance)
}

async fn get_session_blocks(serai: &TemporalSerai<'_>, session: u32) -> u64 {
  let begin_block = serai
    .validator_sets()
    .session_begin_block(NetworkId::Serai, Session(session))
    .await
    .unwrap()
    .unwrap();

  let next_begin_block = serai
    .validator_sets()
    .session_begin_block(NetworkId::Serai, Session(session + 1))
    .await
    .unwrap()
    .unwrap();

  next_begin_block.saturating_sub(begin_block)
}
