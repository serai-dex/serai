pub use serai_abi::{
  primitives::instructions::SignedBatch,
  in_instructions::{Call, Event},
  UnsignedCall, Transaction,
};

use crate::{RpcError, TemporalSerai};

/// A `TemporalSerai` scoped to the in instructions module.
#[derive(Clone)]
pub struct InInstructions<'serai>(pub(super) &'serai TemporalSerai<'serai>);

impl<'serai> InInstructions<'serai> {
  /// The events from the in instructions module.
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
          serai_abi::Event::InInstructions(event) => Some(event.clone()),
          _ => None,
        })
        .collect(),
    )
  }

  /// The `Batch` events from the in instructions module.
  pub async fn batch_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::Batch { .. }))
        .collect(),
    )
  }

  /// Create a transaction to execute a batch.
  pub fn execute_batch(batch: SignedBatch) -> Transaction {
    Transaction::Unsigned {
      call: UnsignedCall::try_from(serai_abi::Call::from(Call::execute_batch { batch }))
        .expect("`execute_batch` wasn't an unsigned call?"),
    }
  }
}
