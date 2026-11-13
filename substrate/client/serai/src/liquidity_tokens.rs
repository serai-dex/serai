use serai_abi::primitives::{
  address::SeraiAddress,
  balance::{Amount, ExternalBalance},
  coin::ExternalCoin,
};

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

  /// Check whether Serai will allow minting of the given liquidity balance.
  pub async fn allow_liquidity_mint(&self, balance: ExternalBalance) -> Result<bool, RpcError> {
    self
      .call::<bool>(
        "liquidity-tokens/allow-mint",
        &format!(r#", "coin": {}, "amount": {:?} "#, rpc_coin(balance.coin), balance.amount),
      )
      .await
  }
}
