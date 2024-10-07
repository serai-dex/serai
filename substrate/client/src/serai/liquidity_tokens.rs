use scale::Encode;

use serai_abi::primitives::{Amount, ExternalBalance, ExternalCoin, SeraiAddress};

use crate::{TemporalSerai, SeraiError};

const PALLET: &str = "LiquidityTokens";

#[derive(Clone, Copy)]
pub struct SeraiLiquidityTokens<'a>(pub(crate) &'a TemporalSerai<'a>);
impl<'a> SeraiLiquidityTokens<'a> {
  pub async fn token_supply(&self, coin: ExternalCoin) -> Result<Amount, SeraiError> {
    Ok(self.0.storage(PALLET, "Supply", coin).await?.unwrap_or(Amount(0)))
  }

  pub async fn token_balance(
    &self,
    coin: ExternalCoin,
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

  pub fn transfer(to: SeraiAddress, balance: ExternalBalance) -> serai_abi::Call {
    serai_abi::Call::LiquidityTokens(serai_abi::liquidity_tokens::Call::transfer {
      to,
      balance: balance.into(),
    })
  }

  pub fn burn(balance: ExternalBalance) -> serai_abi::Call {
    serai_abi::Call::LiquidityTokens(serai_abi::liquidity_tokens::Call::burn {
      balance: balance.into(),
    })
  }
}
