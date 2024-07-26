use std::{time::Duration, collections::HashMap};

use rand_core::{RngCore, OsRng};
use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};
use frost::dkg::musig::musig;
use schnorrkel::Schnorrkel;

use serai_client::{
  genesis_liquidity::{
    primitives::{GENESIS_LIQUIDITY_ACCOUNT, INITIAL_GENESIS_LP_SHARES},
    SeraiGenesisLiquidity,
  },
  validator_sets::primitives::{musig_context, Session, ValidatorSet},
};

use serai_abi::{
  genesis_liquidity::primitives::{oraclize_values_message, Values},
  primitives::COINS,
};

use sp_core::{sr25519::Signature, Pair as PairTrait};

use serai_client::{
  primitives::{
    Amount, NetworkId, Coin, Balance, BlockHash, SeraiAddress, insecure_pair_from_name, GENESIS_SRI,
  },
  in_instructions::primitives::{InInstruction, InInstructionWithBalance, Batch},
  Serai,
};

use crate::common::{in_instructions::provide_batch, tx::publish_tx};

#[allow(dead_code)]
pub async fn test_genesis_liquidity(serai: Serai) -> HashMap<NetworkId, u32> {
  // all coins except the native
  let coins = COINS.into_iter().filter(|c| *c != Coin::native()).collect::<Vec<_>>();

  // make accounts with amounts
  let mut accounts = HashMap::new();
  for coin in coins.clone() {
    // make 5 accounts per coin
    let mut values = vec![];
    for _ in 0 .. 5 {
      let mut address = SeraiAddress::new([0; 32]);
      OsRng.fill_bytes(&mut address.0);
      values.push((address, Amount(OsRng.next_u64() % 10u64.pow(coin.decimals()))));
    }
    accounts.insert(coin, values);
  }

  // send a batch per coin
  let mut batch_ids: HashMap<NetworkId, u32> = HashMap::new();
  for coin in coins.clone() {
    // set up instructions
    let instructions = accounts[&coin]
      .iter()
      .map(|(addr, amount)| InInstructionWithBalance {
        instruction: InInstruction::GenesisLiquidity(*addr),
        balance: Balance { coin, amount: *amount },
      })
      .collect::<Vec<_>>();

    // set up bloch hash
    let mut block = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block.0);

    // set up batch id
    batch_ids
      .entry(coin.network())
      .and_modify(|v| {
        *v += 1;
      })
      .or_insert(0);

    let batch =
      Batch { network: coin.network(), id: batch_ids[&coin.network()], block, instructions };
    provide_batch(&serai, batch).await;
  }

  // set values relative to each other. We can do that without checking for genesis period blocks
  // since we are running in test(fast-epoch) mode.
  // TODO: Random values here
  let values = Values { monero: 184100, ether: 4785000, dai: 1500 };
  set_values(&serai, &values).await;
  let values_map = HashMap::from([
    (Coin::Monero, values.monero),
    (Coin::Ether, values.ether),
    (Coin::Dai, values.dai),
  ]);

  // wait until genesis is complete
  while serai
    .as_of_latest_finalized_block()
    .await
    .unwrap()
    .genesis_liquidity()
    .genesis_complete()
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
  for coin in coins.clone() {
    let total_coin = accounts[&coin].iter().fold(0u128, |acc, value| acc + u128::from(value.1 .0));
    let value = if coin != Coin::Bitcoin {
      (total_coin * u128::from(values_map[&coin])) / 10u128.pow(coin.decimals())
    } else {
      total_coin
    };

    total_value += value;
    pool_amounts.insert(coin, (total_coin, value));
  }

  // check distributed SRI per pool
  let mut total_sri_distributed = 0u128;
  for coin in coins.clone() {
    let sri = if coin == *COINS.last().unwrap() {
      u128::from(GENESIS_SRI).checked_sub(total_sri_distributed).unwrap()
    } else {
      (pool_amounts[&coin].1 * u128::from(GENESIS_SRI)) / total_value
    };
    total_sri_distributed += sri;

    let reserves = serai.dex().get_reserves(coin).await.unwrap().unwrap();
    assert_eq!(u128::from(reserves.0), pool_amounts[&coin].0); // coin side
    assert_eq!(u128::from(reserves.1), sri); // SRI side
  }

  // check each liquidity provider got liquidity tokens proportional to their value
  for coin in coins {
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

  batch_ids
}

#[allow(dead_code)]
async fn set_values(serai: &Serai, values: &Values) {
  // prepare a Musig tx to oraclize the relative values
  let pair = insecure_pair_from_name("Alice");
  let public = pair.public();
  // we publish the tx in set 1
  let set = ValidatorSet { session: Session(1), network: NetworkId::Serai };

  let public_key = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut public.0.as_ref()).unwrap();
  let secret_key = <Ristretto as Ciphersuite>::read_F::<&[u8]>(
    &mut pair.as_ref().secret.to_bytes()[.. 32].as_ref(),
  )
  .unwrap();

  assert_eq!(Ristretto::generator() * secret_key, public_key);
  let threshold_keys =
    musig::<Ristretto>(&musig_context(set), &Zeroizing::new(secret_key), &[public_key]).unwrap();

  let sig = frost::tests::sign_without_caching(
    &mut OsRng,
    frost::tests::algorithm_machines(
      &mut OsRng,
      &Schnorrkel::new(b"substrate"),
      &HashMap::from([(threshold_keys.params().i(), threshold_keys.into())]),
    ),
    &oraclize_values_message(&set, values),
  );

  // oraclize values
  let _ =
    publish_tx(serai, &SeraiGenesisLiquidity::oraclize_values(*values, Signature(sig.to_bytes())))
      .await;
}
