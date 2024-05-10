use std::{time::Duration, collections::HashMap};

use serai_client::TemporalSerai;

use serai_abi::{
  emissions::primitives::{INITIAL_REWARD_PER_BLOCK, SECURE_BY},
  primitives::{Coin, COINS, NETWORKS},
};

use serai_client::{
  primitives::{Amount, NetworkId, Balance},
  Serai,
};

mod common;
use common::genesis_liquidity::test_genesis_liquidity;

serai_test_fast_epoch!(
  emissions: (|serai: Serai| async move {
    test_emissions(serai).await;
  })
);

async fn test_emissions(serai: Serai) {
  // provide some genesis liquidity
  test_genesis_liquidity(serai.clone()).await;

  let mut last_epoch_start = 0;
  for i in 1 .. 3 {
    let mut current_stake = HashMap::new();
    for n in NETWORKS {
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

    // wait until we have at least 1 session
    wait_for_session(&serai, i).await;

    // get distances to ec security
    let last_block = serai.latest_finalized_block().await.unwrap();
    let serai_latest = serai.as_of(last_block.hash());
    let (distances, total_distance) = get_distances(&serai_latest, &current_stake).await;

    // calculate how much reward in this session
    let block_count = last_block.number() - last_epoch_start;
    let reward_this_epoch = if i == 1 {
      // last block number should be the block count since we are in the first block of session 1.
      block_count * INITIAL_REWARD_PER_BLOCK
    } else {
      let blocks_until = SECURE_BY - last_block.number();
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

    for (n, reward) in reward_per_network {
      let stake = serai_latest
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

    last_epoch_start = last_block.number();
  }
}

/// Returns the required stake in terms SRI for a given `Balance`.
async fn required_stake(serai: &TemporalSerai<'_>, balance: Balance) -> u64 {
  // This is inclusive to an increase in accuracy
  let sri_per_coin = serai.dex().oracle_value(balance.coin).await.unwrap().unwrap_or(Amount(0));

  // See dex-pallet for the reasoning on these
  let coin_decimals = balance.coin.decimals().max(5);
  let accuracy_increase = u128::from(u64::pow(10, coin_decimals));

  let total_coin_value =
    u64::try_from(u128::from(balance.amount.0) * u128::from(sri_per_coin.0) / accuracy_increase)
      .unwrap_or(u64::MAX);

  // required stake formula (COIN_VALUE * 1.5) + margin(20%)
  let required_stake = total_coin_value.saturating_mul(3).saturating_div(2);
  required_stake.saturating_add(total_coin_value.saturating_div(5))
}

async fn wait_for_session(serai: &Serai, session: u32) {
  // Epoch time is half an hour with the fast epoch feature, so lets wait double that.
  tokio::time::timeout(tokio::time::Duration::from_secs(60 * 6), async {
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
      session
    {
      tokio::time::sleep(Duration::from_secs(6)).await;
    }
  })
  .await
  .unwrap();
}

async fn get_distances(
  serai: &TemporalSerai<'_>,
  current_stake: &HashMap<NetworkId, u64>,
) -> (HashMap<NetworkId, u64>, u64) {
  // we should be in the initial period, so calculate how much each network supposedly get..
  // we can check the supply to see how much coin hence liability we have.
  let mut distances: HashMap<NetworkId, u64> = HashMap::new();
  let mut total_distance = 0;
  for coin in COINS {
    if coin == Coin::Serai {
      continue;
    }

    let amount = serai.coins().coin_supply(coin).await.unwrap();
    let required = required_stake(&serai, Balance { coin, amount }).await;
    let mut current = *current_stake.get(&coin.network()).unwrap();
    if current > required {
      current = required;
    }

    let distance = required - current;
    total_distance += distance;

    distances.insert(
      coin.network(),
      distances.get(&coin.network()).unwrap_or(&0).saturating_add(distance),
    );
  }

  // add serai network portion(20%)
  let new_total_distance = total_distance.saturating_mul(10) / 8;
  distances.insert(NetworkId::Serai, new_total_distance - total_distance);
  total_distance = new_total_distance;

  (distances, total_distance)
}
