use std::{time::Duration, collections::HashMap};

use serai_client::TemporalSerai;

use serai_abi::{
  emissions::primitives::INITIAL_REWARD_PER_BLOCK,
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

  // wait until we have at least 1 session, epoch time is half an hour with the fast epoch
  // feature, so lets wait double that.
  tokio::time::timeout(tokio::time::Duration::from_secs(60 * 3), async {
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
      1
    {
      tokio::time::sleep(Duration::from_secs(6)).await;
    }
  })
  .await
  .unwrap();

  let last_block = serai.latest_finalized_block().await.unwrap();
  let serai_latest = serai.as_of(last_block.hash());

  // we should be in the initial period, so calculate how much each network supposedly get..
  // we can check the supply to see how much coin hence liability we have.
  let mut distances: HashMap<NetworkId, u64> = HashMap::new();
  let mut total_distance = 0;
  for coin in COINS {
    if coin == Coin::Serai {
      continue;
    }

    let amount = serai_latest.coins().coin_supply(coin).await.unwrap();
    let required = required_stake(&serai_latest, Balance { coin, amount }).await;
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

  // since we should be in the first block after the first epoch, block number should also
  // give us the block count.
  let block_count = last_block.number();
  let reward_this_epoch = block_count * INITIAL_REWARD_PER_BLOCK;

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
    let stake =
      serai_latest.validator_sets().total_allocated_stake(n).await.unwrap().unwrap_or(Amount(0)).0;

    // the reward should have been automatically staked for the network
    assert_eq!(stake, *current_stake.get(&n).unwrap() + reward);
  }

  // TODO: check stake per address
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
