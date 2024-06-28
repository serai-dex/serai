use std::{time::Duration, collections::HashMap};

use rand_core::{RngCore, OsRng};
use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};
use frost::dkg::musig::musig;
use schnorrkel::Schnorrkel;

use serai_client::{
  genesis_liquidity::{
    primitives::{GENESIS_LIQUIDITY_ACCOUNT, GENESIS_LP_SHARES},
    SeraiGenesisLiquidity,
  },
  validator_sets::primitives::{musig_context, Session, ValidatorSet},
};

use serai_abi::{
  genesis_liquidity::primitives::{set_initial_price_message, Prices},
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

mod common;
use common::{in_instructions::provide_batch, tx::publish_tx};

serai_test_fast_epoch!(
  genesis_liquidity: (|serai: Serai| async move {
    test_genesis_liquidity(serai).await;
  })
);

async fn test_genesis_liquidity(serai: Serai) {
  // amounts
  let amounts = vec![
    Amount(5_53246991),
    Amount(3_14562819),
    Amount(9_33648912),
    Amount(150_873639000000),
    Amount(248_665228000000),
    Amount(451_765529000000),
  ];

  // addresses
  let mut btc_addresses = vec![];
  let mut xmr_addresses = vec![];
  let addr_count = amounts.len();
  for (i, amount) in amounts.into_iter().enumerate() {
    let mut address = SeraiAddress::new([0; 32]);
    OsRng.fill_bytes(&mut address.0);
    if i < addr_count / 2 {
      btc_addresses.push((address, amount));
    } else {
      xmr_addresses.push((address, amount));
    }
  }

  // btc batch
  let mut block_hash = BlockHash([0; 32]);
  OsRng.fill_bytes(&mut block_hash.0);
  let btc_ins = btc_addresses
    .iter()
    .map(|(addr, amount)| InInstructionWithBalance {
      instruction: InInstruction::GenesisLiquidity(*addr),
      balance: Balance { coin: Coin::Bitcoin, amount: *amount },
    })
    .collect::<Vec<_>>();
  let batch =
    Batch { network: NetworkId::Bitcoin, id: 0, block: block_hash, instructions: btc_ins };
  provide_batch(&serai, batch).await;

  // xmr batch
  let mut block_hash = BlockHash([0; 32]);
  OsRng.fill_bytes(&mut block_hash.0);
  let xmr_ins = xmr_addresses
    .iter()
    .map(|(addr, amount)| InInstructionWithBalance {
      instruction: InInstruction::GenesisLiquidity(*addr),
      balance: Balance { coin: Coin::Monero, amount: *amount },
    })
    .collect::<Vec<_>>();
  let batch = Batch { network: NetworkId::Monero, id: 0, block: block_hash, instructions: xmr_ins };
  provide_batch(&serai, batch).await;

  // wait until genesis ends..
  tokio::time::timeout(tokio::time::Duration::from_secs(300), async {
    while serai.latest_finalized_block().await.unwrap().number() < 10 {
      tokio::time::sleep(Duration::from_secs(6)).await;
    }
  })
  .await
  .unwrap();

  // set prices
  let prices = Prices { bitcoin: 10u64.pow(8), monero: 184100, ethereum: 4785000, dai: 1500 };
  set_prices(&serai, &prices).await;

  // wait little bit..
  tokio::time::sleep(Duration::from_secs(12)).await;

  // check total SRI supply is +100M
  let last_block = serai.latest_finalized_block().await.unwrap().hash();
  let serai = serai.as_of(last_block);
  let sri = serai.coins().coin_supply(Coin::Serai).await.unwrap();
  // there are 6 endowed accounts in dev-net. Take this into consideration when checking
  // for the total sri minted at this time.
  let endowed_amount: u64 = 1 << 60;
  let total_sri = (6 * endowed_amount) + GENESIS_SRI;
  assert_eq!(sri, Amount(total_sri));

  // check genesis account has no coins, all transferred to pools.
  for coin in COINS {
    let amount = serai.coins().coin_balance(coin, GENESIS_LIQUIDITY_ACCOUNT).await.unwrap();
    assert_eq!(amount.0, 0);
  }

  // check pools has proper liquidity
  let pool_btc = btc_addresses.iter().fold(0u128, |acc, value| acc + u128::from(value.1 .0));
  let pool_xmr = xmr_addresses.iter().fold(0u128, |acc, value| acc + u128::from(value.1 .0));

  let pool_btc_value = (pool_btc * u128::from(prices.bitcoin)) / 10u128.pow(8);
  let pool_xmr_value = (pool_xmr * u128::from(prices.monero)) / 10u128.pow(12);
  let total_value = pool_btc_value + pool_xmr_value;

  // calculated distributed SRI. We know that xmr is at the end of COINS array
  // so it will be approximated to roof instead of floor after integer division.
  let btc_sri = (pool_btc_value * u128::from(GENESIS_SRI)) / total_value;
  let xmr_sri = ((pool_xmr_value * u128::from(GENESIS_SRI)) / total_value) + 1;

  let btc_reserves = serai.dex().get_reserves(Coin::Bitcoin).await.unwrap().unwrap();
  assert_eq!(u128::from(btc_reserves.0 .0), pool_btc);
  assert_eq!(u128::from(btc_reserves.1 .0), btc_sri);

  let xmr_reserves = serai.dex().get_reserves(Coin::Monero).await.unwrap().unwrap();
  assert_eq!(u128::from(xmr_reserves.0 .0), pool_xmr);
  assert_eq!(u128::from(xmr_reserves.1 .0), xmr_sri);

  // check each btc liq provider got liq tokens proportional to their value
  let btc_liq_supply = serai.genesis_liquidity().supply(Coin::Bitcoin).await.unwrap();
  for (acc, amount) in btc_addresses {
    let acc_liq_shares =
      serai.genesis_liquidity().liquidity(&acc, Coin::Bitcoin).await.unwrap().0 .0;

    // since we can't test the ratios directly(due to integer division giving 0)
    // we test whether they give the same result when multiplied by another constant.
    // Following test ensures the account in fact has the right amount of shares.
    let shares_ratio = (GENESIS_LP_SHARES * acc_liq_shares) / btc_liq_supply.0 .0;
    let amounts_ratio = (GENESIS_LP_SHARES * amount.0) / u64::try_from(pool_btc).unwrap();
    assert_eq!(shares_ratio, amounts_ratio);
  }

  // check each xmr liq provider got liq tokens proportional to their value
  let xmr_liq_supply = serai.genesis_liquidity().supply(Coin::Monero).await.unwrap();
  for (acc, amount) in xmr_addresses {
    let acc_liq_shares =
      serai.genesis_liquidity().liquidity(&acc, Coin::Monero).await.unwrap().0 .0;

    let shares_ratio = (GENESIS_LP_SHARES * acc_liq_shares) / xmr_liq_supply.0 .0;
    let amounts_ratio = (GENESIS_LP_SHARES * amount.0) / u64::try_from(pool_xmr).unwrap();
    assert_eq!(shares_ratio, amounts_ratio);
  }

  // TODO: test remove the liq before/after genesis ended.
}

async fn set_prices(serai: &Serai, prices: &Prices) {
  // prepare a Musig tx to set the initial prices
  let pair = insecure_pair_from_name("Alice");
  let public = pair.public();
  let set = ValidatorSet { session: Session(0), network: NetworkId::Serai };

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
    &set_initial_price_message(&set, prices),
  );

  // set initial prices
  let _ = publish_tx(
    serai,
    &SeraiGenesisLiquidity::set_initial_price(*prices, Signature(sig.to_bytes())),
  )
  .await;
}
