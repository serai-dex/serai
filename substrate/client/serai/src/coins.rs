pub use serai_abi::coins::Event;

use serai_abi::primitives::{address::SeraiAddress, balance::Amount, coin::Coin};

use crate::{Events, RpcError, State, rpc_coin};

/// An `Events` scoped to the coins module.
#[derive(Clone)]
pub struct Coins(pub(super) Events);

impl Coins {
  /// The events from the coins module.
  pub fn events(&self) -> impl Iterator<Item = &Event> {
    #[expect(clippy::wildcard_enum_match_arm)]
    self.0.events().flatten().filter_map(|event| match event {
      serai_abi::Event::Coins(event) => Some(event),
      _ => None,
    })
  }

  /// The `Mint` events from the coins module.
  pub fn mint_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::Mint { .. }))
  }

  /// The `Transfer` events from the coins module.
  pub fn transfer_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::Transfer { .. }))
  }

  /// The `Burn` events from the coins module.
  pub fn burn_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::Burn { .. }))
  }

  /// The `BurnWithInstruction` events from the coins module.
  pub fn burn_with_instruction_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::BurnWithInstruction { .. }))
  }
}

impl State<'_> {
  /// Return balance of a given account for coin.
  pub async fn balance(&self, of: SeraiAddress, coin: Coin) -> Result<Amount, RpcError> {
    Ok(Amount(
      self
        .call::<u64>(
          "coins/balance",
          &format!(r#", "address": "{of}", "coin": {} "#, rpc_coin(coin)),
        )
        .await?,
    ))
  }

  /// Return supply of a given coin.
  pub async fn supply(&self, coin: Coin) -> Result<Amount, RpcError> {
    Ok(Amount(
      self.call::<u64>("coins/supply", &format!(r#", "coin": {} "#, rpc_coin(coin))).await?,
    ))
  }
}
