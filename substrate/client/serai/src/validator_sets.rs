pub use serai_abi::validator_sets::Event;
use crate::{RpcError, TemporalSerai};

/// A `TemporalSerai` scoped to the validator sets module.
#[derive(Clone)]
pub struct ValidatorSets<'a>(pub(super) &'a TemporalSerai<'a>);

impl<'a> ValidatorSets<'a> {
  /// The events from the validator sets module.
  pub async fn events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .0
        .events()
        .await?
        .as_ref()
        .expect("`TemporalSerai::events` returned None")
        .iter()
        .filter_map(|event| match event {
          serai_abi::Event::ValidatorSets(event) => Some(event.clone()),
          _ => None,
        })
        .collect(),
    )
  }

  /// The `SetDecided` events from the validator sets module.
  pub async fn set_decided_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::SetDecided { .. }))
        .collect(),
    )
  }

  /// The `AcceptedHandover` events from the validator sets module.
  pub async fn accepted_handover_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::AcceptedHandover { .. }))
        .collect(),
    )
  }
}
