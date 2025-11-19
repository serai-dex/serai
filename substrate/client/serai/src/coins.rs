pub use serai_abi::coins::Event;

use crate::{RpcError, Events};

/// An `Events` scoped to the coins module.
#[derive(Clone)]
pub struct Coins(pub(super) Events);

impl Coins {
  /// The events from the coins module.
  pub fn events(&self) -> impl Iterator<Item = &Event> {
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
