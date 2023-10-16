use serai_runtime::{
  primitives::{SeraiAddress, SubstrateAmount, Amount, Coin, Balance},
  coins, Coins, Runtime,
};
pub use coins::primitives;
use primitives::OutInstruction;

use subxt::tx::Payload;

use crate::{TemporalSerai, SeraiError, Composite, scale_value, scale_composite};

const PALLET: &str = "Coins";

pub type CoinsEvent = coins::Event<Runtime>;

#[derive(Clone, Copy)]
pub struct SeraiCoins<'a>(pub(crate) TemporalSerai<'a>);
impl<'a> SeraiCoins<'a> {
  pub fn into_inner(self) -> TemporalSerai<'a> {
    self.0
  }

  pub async fn mint_events(&self) -> Result<Vec<CoinsEvent>, SeraiError> {
    self.0.events::<Coins, _>(|event| matches!(event, CoinsEvent::Mint { .. })).await
  }

  pub async fn burn_events(&self) -> Result<Vec<CoinsEvent>, SeraiError> {
    self.0.events::<Coins, _>(|event| matches!(event, CoinsEvent::Burn { .. })).await
  }

  pub async fn sri_balance(&self, address: SeraiAddress) -> Result<u64, SeraiError> {
    let amount: Option<SubstrateAmount> = self
      .0
      .storage(PALLET, "Coins", Some(vec![scale_value(address), scale_value(Coin::Serai)]))
      .await?;
    Ok(amount.unwrap_or(0))
  }

  // TODO: shouldn't these token functions be renamed to coins now?
  pub async fn token_supply(&self, coin: Coin) -> Result<Amount, SeraiError> {
    Ok(Amount(
      self
        .0
        .storage::<SubstrateAmount>(PALLET, "Supply", Some(vec![scale_value(coin)]))
        .await?
        .unwrap_or(0),
    ))
  }

  pub async fn token_balance(
    &self,
    coin: Coin,
    address: SeraiAddress,
  ) -> Result<Amount, SeraiError> {
    Ok(Amount(
      self
        .0
        .storage::<SubstrateAmount>(
          PALLET,
          "Coins",
          Some(vec![scale_value(address), scale_value(coin)]),
        )
        .await?
        .unwrap_or(0),
    ))
  }

  pub fn transfer_sri(to: SeraiAddress, amount: Amount) -> Payload<Composite<()>> {
    Payload::new(
      PALLET,
      "transfer",
      scale_composite(serai_runtime::coins::Call::<Runtime>::transfer {
        to,
        coin: Coin::Serai,
        amount: amount.0,
      }),
    )
  }

  pub fn burn(balance: Balance, instruction: OutInstruction) -> Payload<Composite<()>> {
    Payload::new(
      PALLET,
      "burn",
      scale_composite(coins::Call::<Runtime>::burn { balance, instruction: Some(instruction) }),
    )
  }
}
