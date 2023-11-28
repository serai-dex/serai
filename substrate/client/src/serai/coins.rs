use scale::Encode;

use serai_runtime::{
  primitives::{SeraiAddress, Amount, Coin, Balance},
  coins, Runtime,
};
pub use coins::primitives;
use primitives::OutInstructionWithBalance;

use crate::{TemporalSerai, SeraiError};

const PALLET: &str = "Coins";

pub type CoinsEvent = coins::Event<Runtime>;

#[derive(Clone, Copy)]
pub struct SeraiCoins<'a>(pub(crate) TemporalSerai<'a>);
impl<'a> SeraiCoins<'a> {
  pub fn into_inner(self) -> TemporalSerai<'a> {
    self.0
  }

  pub async fn mint_events(&self) -> Result<Vec<CoinsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_runtime::RuntimeEvent::Coins(event) = event {
          Some(event).filter(|event| matches!(event, CoinsEvent::Mint { .. }))
        } else {
          None
        }
      })
      .await
  }

  pub async fn burn_with_instruction_events(&self) -> Result<Vec<CoinsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_runtime::RuntimeEvent::Coins(event) = event {
          Some(event).filter(|event| matches!(event, CoinsEvent::BurnWithInstruction { .. }))
        } else {
          None
        }
      })
      .await
  }

  pub async fn coin_supply(&self, coin: Coin) -> Result<Amount, SeraiError> {
    Ok(self.0.storage(PALLET, "Supply", coin).await?.unwrap_or(Amount(0)))
  }

  pub async fn coin_balance(
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

  pub fn transfer(to: SeraiAddress, balance: Balance) -> serai_runtime::RuntimeCall {
    serai_runtime::RuntimeCall::Coins(serai_runtime::coins::Call::<Runtime>::transfer {
      to: to.into(),
      balance,
    })
  }

  pub fn burn(balance: Balance) -> serai_runtime::RuntimeCall {
    serai_runtime::RuntimeCall::Coins(serai_runtime::coins::Call::<Runtime>::burn { balance })
  }

  pub fn burn_with_instruction(
    instruction: OutInstructionWithBalance,
  ) -> serai_runtime::RuntimeCall {
    serai_runtime::RuntimeCall::Coins(
      serai_runtime::coins::Call::<Runtime>::burn_with_instruction { instruction },
    )
  }
}
