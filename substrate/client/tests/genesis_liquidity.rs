use std::{time::Duration, collections::HashMap};

use serai_client::Serai;

use serai_abi::primitives::{Amount, Coin, ExternalCoin, COINS, EXTERNAL_COINS, GENESIS_SRI};

use serai_client::genesis_liquidity::primitives::{
  GENESIS_LIQUIDITY_ACCOUNT, INITIAL_GENESIS_LP_SHARES,
};

mod common;
use common::genesis_liquidity::set_up_genesis;

serai_test_fast_epoch!(
  genesis_liquidity: (|serai: Serai| async move {
    test_genesis_liquidity(serai).await;
  })
);

pub async fn test_genesis_liquidity(serai: Serai) {
  // set up the genesis
  let values = HashMap::from([
    (ExternalCoin::Monero, 184100),
    (ExternalCoin::Ether, 4785000),
    (ExternalCoin::Dai, 1500),
  ]);
  let (accounts, _) = set_up_genesis(&serai, &values).await;

  // wait until genesis is complete
  while serai
    .as_of_latest_finalized_block()
    .await
    .unwrap()
    .genesis_liquidity()
    .genesis_complete_block()
    .await
    .unwrap()
    .is_none()
  {
    tokio::time::sleep(Duration::from_secs(1)).await;
  }

  // check total SRI supply is +100M
  // there are 6 endowed accounts in dev-net. Take this into consideration when checking
  // for the total sri minted at this time.
  let serai = serai.as_of_latest_finalized_block().await.unwrap();
  let sri = serai.coins().coin_supply(Coin::Serai).await.unwrap();
  let endowed_amount: u64 = 1 << 60;
  let total_sri = (6 * endowed_amount) + GENESIS_SRI;
  assert_eq!(sri, Amount(total_sri));

  // check genesis account has no coins, all transferred to pools.
  for coin in COINS {
    let amount = serai.coins().coin_balance(coin, GENESIS_LIQUIDITY_ACCOUNT).await.unwrap();
    assert_eq!(amount.0, 0);
  }

  // check pools has proper liquidity
  let mut pool_amounts = HashMap::new();
  let mut total_value = 0u128;
  for coin in EXTERNAL_COINS {
    let total_coin = accounts[&coin].iter().fold(0u128, |acc, value| acc + u128::from(value.1 .0));
    let value = if coin != ExternalCoin::Bitcoin {
      (total_coin * u128::from(values[&coin])) / 10u128.pow(coin.decimals())
    } else {
      total_coin
    };

    total_value += value;
    pool_amounts.insert(coin, (total_coin, value));
  }

  // check distributed SRI per pool
  let mut total_sri_distributed = 0u128;
  for coin in EXTERNAL_COINS {
    let sri = if coin == *EXTERNAL_COINS.last().unwrap() {
      u128::from(GENESIS_SRI).checked_sub(total_sri_distributed).unwrap()
    } else {
      (pool_amounts[&coin].1 * u128::from(GENESIS_SRI)) / total_value
    };
    total_sri_distributed += sri;

    let reserves = serai.dex().get_reserves(coin).await.unwrap().unwrap();
    assert_eq!(u128::from(reserves.0 .0), pool_amounts[&coin].0); // coin side
    assert_eq!(u128::from(reserves.1 .0), sri); // SRI side
  }

  // check each liquidity provider got liquidity tokens proportional to their value
  for coin in EXTERNAL_COINS {
    let liq_supply = serai.genesis_liquidity().supply(coin).await.unwrap();
    for (acc, amount) in &accounts[&coin] {
      let acc_liq_shares = serai.genesis_liquidity().liquidity(acc, coin).await.unwrap().shares;

      // since we can't test the ratios directly(due to integer division giving 0)
      // we test whether they give the same result when multiplied by another constant.
      // Following test ensures the account in fact has the right amount of shares.
      let mut shares_ratio = (INITIAL_GENESIS_LP_SHARES * acc_liq_shares) / liq_supply.shares;
      let amounts_ratio =
        (INITIAL_GENESIS_LP_SHARES * amount.0) / u64::try_from(pool_amounts[&coin].0).unwrap();

      // we can tolerate 1 unit diff between them due to integer division.
      if shares_ratio.abs_diff(amounts_ratio) == 1 {
        shares_ratio = amounts_ratio;
      }

      assert_eq!(shares_ratio, amounts_ratio);
    }
  }

  // TODO: test remove the liq before/after genesis ended.
}
