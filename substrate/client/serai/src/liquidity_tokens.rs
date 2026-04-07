use serai_abi::primitives::{balance::Amount, address::SeraiAddress, coin::ExternalCoin};

use crate::{RpcError, State, rpc_coin};

impl State<'_> {
  /// Return liquidity balance of a given account for coin.
  pub async fn liquidity_balance(
    &self,
    of: SeraiAddress,
    coin: ExternalCoin,
  ) -> Result<Amount, RpcError> {
    Ok(Amount(
      self
        .call::<u64>(
          "liquidity-tokens/balance",
          &format!(r#", "address": "{of}", "coin": {} "#, rpc_coin(coin)),
        )
        .await?,
    ))
  }

  /// Return liquidity supply of a given coin.
  pub async fn liquidity_supply(&self, coin: ExternalCoin) -> Result<Amount, RpcError> {
    Ok(Amount(
      self
        .call::<u64>("liquidity-tokens/supply", &format!(r#", "coin": {} "#, rpc_coin(coin)))
        .await?,
    ))
  }
}
