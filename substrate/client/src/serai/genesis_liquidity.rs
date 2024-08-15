pub use serai_abi::genesis_liquidity::primitives;
use primitives::{Values, LiquidityAmount};

use serai_abi::primitives::*;

use sp_core::sr25519::Signature;

use scale::Encode;

use crate::{Serai, SeraiError, TemporalSerai, Transaction};

pub type GenesisLiquidityEvent = serai_abi::genesis_liquidity::Event;

const PALLET: &str = "GenesisLiquidity";

#[derive(Clone, Copy)]
pub struct SeraiGenesisLiquidity<'a>(pub(crate) &'a TemporalSerai<'a>);
impl<'a> SeraiGenesisLiquidity<'a> {
  pub async fn events(&self) -> Result<Vec<GenesisLiquidityEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_abi::Event::GenesisLiquidity(event) = event {
          Some(event.clone())
        } else {
          None
        }
      })
      .await
  }

  pub fn oraclize_values(values: Values, signature: Signature) -> Transaction {
    Serai::unsigned(serai_abi::Call::GenesisLiquidity(
      serai_abi::genesis_liquidity::Call::oraclize_values { values, signature },
    ))
  }

  pub fn remove_coin_liquidity(balance: Balance) -> serai_abi::Call {
    serai_abi::Call::GenesisLiquidity(serai_abi::genesis_liquidity::Call::remove_coin_liquidity {
      balance,
    })
  }

  pub async fn liquidity(
    &self,
    address: &SeraiAddress,
    coin: Coin,
  ) -> Result<LiquidityAmount, SeraiError> {
    Ok(
      self
        .0
        .storage(
          PALLET,
          "Liquidity",
          (coin, sp_core::hashing::blake2_128(&address.encode()), &address.0),
        )
        .await?
        .unwrap_or(LiquidityAmount::zero()),
    )
  }

  pub async fn supply(&self, coin: Coin) -> Result<LiquidityAmount, SeraiError> {
    Ok(self.0.storage(PALLET, "Supply", coin).await?.unwrap_or(LiquidityAmount::zero()))
  }

  pub async fn genesis_complete_block(&self) -> Result<Option<u64>, SeraiError> {
    self.0.storage(PALLET, "GenesisCompleteBlock", ()).await
  }
}
