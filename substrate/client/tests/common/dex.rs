use serai_abi::primitives::{Coin, Amount};

use serai_client::{Serai, SeraiDex};
use sp_core::{sr25519::Pair, Pair as PairTrait};

use crate::common::tx::publish_tx;

#[allow(dead_code)]
pub async fn add_liquidity(
  serai: &Serai,
  coin: Coin,
  coin_amount: Amount,
  sri_amount: Amount,
  nonce: u32,
  pair: Pair,
) -> [u8; 32] {
  let address = pair.public();

  let tx = serai.sign(
    &pair,
    SeraiDex::add_liquidity(coin, coin_amount, sri_amount, Amount(1), Amount(1), address.into()),
    nonce,
    0,
  );

  publish_tx(serai, &tx).await
}

#[allow(dead_code)]
pub async fn swap(
  serai: &Serai,
  from_coin: Coin,
  to_coin: Coin,
  amount_in: Amount,
  amount_out_min: Amount,
  nonce: u32,
  pair: Pair,
) -> [u8; 32] {
  let address = pair.public();

  let tx = serai.sign(
    &pair,
    SeraiDex::swap(from_coin, to_coin, amount_in, amount_out_min, address.into()),
    nonce,
    Default::default(),
  );

  publish_tx(serai, &tx).await
}
