use scale::Encode;

use serai_abi::primitives::{SeraiAddress, Amount, Coin, Balance};

use crate::{TemporalSerai, SeraiError};

const PALLET: &str = "LiquidityTokens";

#[derive(Clone, Copy)]
pub struct SeraiLiquidityTokens<'a>(pub(crate) &'a TemporalSerai<'a>);
impl<'a> SeraiLiquidityTokens<'a> {
  pub async fn token_supply(&self, coin: Coin) -> Result<Amount, SeraiError> {
    Ok(self.0.storage(PALLET, "Supply", coin).await?.unwrap_or(Amount(0)))
  }

  pub async fn token_balance(
    &self,
    coin: Coin,
    address: SeraiAddress,
  ) -> Result<Amount, SeraiError> {
    Ok(
      self
        .0
        .storage(
          PALLET,
          "Balances",
          (sp_core::hashing::blake2_128(&address.encode()), &address.0, coin),
        )
        .await?
        .unwrap_or(Amount(0)),
    )
  }

  pub fn transfer(to: SeraiAddress, balance: Balance) -> serai_abi::Call {
    serai_abi::Call::Coins(serai_abi::coins::Call::transfer { to, balance })
  }

  pub fn burn(balance: Balance) -> serai_abi::Call {
    serai_abi::Call::Coins(serai_abi::coins::Call::burn { balance })
  }
}
