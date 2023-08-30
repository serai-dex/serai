use serai_runtime::primitives::{Coin, Amount};

use serai_client::{Serai, PairSigner};
use sp_core::{sr25519::Pair, Pair as PairTrait};

use subxt::config::extrinsic_params::BaseExtrinsicParamsBuilder;

use crate::common::{serai, tx::publish_tx};

#[allow(dead_code)]
pub async fn create_pool(asset: Coin, pair: Pair) -> [u8; 32] {
  let serai = serai().await;

  let tx = serai
    .sign(&PairSigner::new(pair), &Serai::create_pool(asset), 0, BaseExtrinsicParamsBuilder::new())
    .unwrap();

  // TODO: this func should panic if can't found the tx?
  publish_tx(&tx).await
}

#[allow(dead_code)]
pub async fn add_liquidity(
  asset: Coin,
  asset_amount: Amount,
  sri_amount: Amount,
  pair: Pair,
) -> [u8; 32] {
  let serai = serai().await;
  let address = pair.public();

  let tx = serai
    .sign(
      &PairSigner::new(pair),
      &Serai::add_liquidity(asset, asset_amount.0, sri_amount.0, 1, 1, address.into()),
      // TODO: we should handle the nonces better in tests. This nonce is
      // 1 because we have to make create_pool call first and nonce of that is 0.
      // maybe take it as parameter but just seems like delaying the problem.
      1,
      BaseExtrinsicParamsBuilder::new(),
    )
    .unwrap();

  publish_tx(&tx).await
}
