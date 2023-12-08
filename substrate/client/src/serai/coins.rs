use scale::Encode;

use serai_abi::primitives::{SeraiAddress, Amount, Coin, Balance};
pub use serai_abi::coins::primitives;
use primitives::OutInstructionWithBalance;

use crate::{TemporalSerai, SeraiError};

const PALLET: &str = "Coins";

pub type CoinsEvent = serai_abi::coins::Event;

#[derive(Clone, Copy)]
pub struct SeraiCoins<'a>(pub(crate) &'a TemporalSerai<'a>);
impl<'a> SeraiCoins<'a> {
  pub async fn mint_events(&self) -> Result<Vec<CoinsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_abi::Event::Coins(event) = event {
          if matches!(event, CoinsEvent::Mint { .. }) {
            Some(event.clone())
          } else {
            None
          }
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
        if let serai_abi::Event::Coins(event) = event {
          if matches!(event, CoinsEvent::BurnWithInstruction { .. }) {
            Some(event.clone())
          } else {
            None
          }
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

  pub fn transfer(to: SeraiAddress, balance: Balance) -> serai_abi::Call {
    serai_abi::Call::Coins(serai_abi::coins::Call::transfer { to, balance })
  }

  pub fn burn(balance: Balance) -> serai_abi::Call {
    serai_abi::Call::Coins(serai_abi::coins::Call::burn { balance })
  }

  pub fn burn_with_instruction(instruction: OutInstructionWithBalance) -> serai_abi::Call {
    serai_abi::Call::Coins(serai_abi::coins::Call::burn_with_instruction { instruction })
  }
}
