use serai_runtime::{
  primitives::{SeraiAddress, SubstrateAmount, Amount, Coin, Balance},
  coins, Coins, Runtime,
};
pub use coins::primitives;
use primitives::OutInstructionWithBalance;

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

  pub async fn coin_supply(&self, coin: Coin) -> Result<Amount, SeraiError> {
    Ok(Amount(
      self
        .0
        .storage::<SubstrateAmount>(PALLET, "Supply", Some(vec![scale_value(coin)]))
        .await?
        .unwrap_or(0),
    ))
  }

  pub async fn coin_balance(
    &self,
    coin: Coin,
    address: SeraiAddress,
  ) -> Result<Amount, SeraiError> {
    Ok(Amount(
      self
        .0
        .storage::<SubstrateAmount>(
          PALLET,
          "Balances",
          Some(vec![scale_value(address), scale_value(coin)]),
        )
        .await?
        .unwrap_or(0),
    ))
  }

  pub fn transfer(to: SeraiAddress, balance: Balance) -> Payload<Composite<()>> {
    Payload::new(
      PALLET,
      "transfer",
      scale_composite(serai_runtime::coins::Call::<Runtime>::transfer { to, balance }),
    )
  }

  pub fn burn(instruction: OutInstructionWithBalance) -> Payload<Composite<()>> {
    Payload::new(PALLET, "burn", scale_composite(coins::Call::<Runtime>::burn { instruction }))
  }
}
