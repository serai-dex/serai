use serai_abi::primitives::{balance::Amount, coin::ExternalCoin, dex::Reserves};

use crate::{RpcError, State, rpc_coin};

impl State<'_> {
  /// Returns reserves for a given pool.
  pub async fn pool_reserves(&self, coin: ExternalCoin) -> Result<Reserves, RpcError> {
    #[derive(Default, core_json_derive::JsonDeserialize)]
    struct ReservesJson {
      sri: u64,
      external_coin: u64,
    }

    let reserves = self
      .call::<ReservesJson>("dex/pool-reserves", &format!(r#", "coin": {} "#, rpc_coin(coin)))
      .await?;

    Ok(Reserves { sri: Amount(reserves.sri), external_coin: Amount(reserves.external_coin) })
  }
}
