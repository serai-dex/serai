pub use serai_abi::coins::Event;

use crate::{RpcError, TemporalSerai};

/// A `TemporalSerai` scoped to the coins module.
#[derive(Clone)]
pub struct Coins<'a>(pub(super) &'a TemporalSerai<'a>);

impl<'a> Coins<'a> {
  /// The events from the coins module.
  pub async fn events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .0
        .events_borrowed()
        .await?
        .as_ref()
        .expect("`TemporalSerai::events` returned None")
        .iter()
        .flat_map(IntoIterator::into_iter)
        .filter_map(|event| match event {
          serai_abi::Event::Coins(event) => Some(event.clone()),
          _ => None,
        })
        .collect(),
    )
  }

  /// The `Mint` events from the coins module.
  pub async fn mint_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::Mint { .. }))
        .collect(),
    )
  }

  /// The `Transfer` events from the coins module.
  pub async fn transfer_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::Transfer { .. }))
        .collect(),
    )
  }

  /// The `Burn` events from the coins module.
  pub async fn burn_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::Burn { .. }))
        .collect(),
    )
  }

  /// The `BurnWithInstruction` events from the coins module.
  pub async fn burn_with_instruction_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::BurnWithInstruction { .. }))
        .collect(),
    )
  }
}
