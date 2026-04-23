use serai_abi::primitives::{balance::Amount, address::SeraiAddress, coin::ExternalCoin};

use crate::{RpcError, State, rpc_coin};

impl State<'_> {
  /// Returns genesis liquidity balance of a given account for coin.
  pub async fn genesis_liquidity_balance(
    &self,
    of: SeraiAddress,
    coin: ExternalCoin,
  ) -> Result<Amount, RpcError> {
    Ok(Amount(
      self
        .call::<u64>(
          "genesis-liquidity/balance",
          &format!(r#", "address": "{of}", "coin": {} "#, rpc_coin(coin)),
        )
        .await?,
    ))
  }

  /// Returns genesis liquidly supply of a given coin.
  pub async fn genesis_liquidity_supply(&self, coin: ExternalCoin) -> Result<Amount, RpcError> {
    Ok(Amount(
      self
        .call::<u64>("genesis-liquidity/supply", &format!(r#", "coin": {} "#, rpc_coin(coin)))
        .await?,
    ))
  }

  /// Returns `true` if the genesis period is completed, `false` otherwise.
  pub async fn genesis_completed(&self) -> Result<bool, RpcError> {
    self.call::<bool>("genesis-liquidity/completed", "").await
  }

  /// Returns the time economic security is achieved first time for all networks.
  /// Returns `0` if it hasn't happen yet.
  pub async fn economic_security_time(&self) -> Result<u64, RpcError> {
    self.call::<u64>("genesis-liquidity/economic-security", "").await
  }
}
