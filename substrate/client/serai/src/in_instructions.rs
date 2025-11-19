pub use serai_abi::{
  primitives::instructions::SignedBatch,
  in_instructions::{Call, Event},
  UnsignedCall, Transaction,
};

use crate::{RpcError, Events};

/// An `Events` scoped to the in instructions module.
#[derive(Clone)]
pub struct InInstructions(pub(super) Events);

impl InInstructions {
  /// The events from the in instructions module.
  fn events(&self) -> impl Iterator<Item = &Event> {
    self.0.events().flatten().filter_map(|event| match event {
      serai_abi::Event::InInstructions(event) => Some(event),
      _ => None,
    })
  }

  /// The `Batch` events from the in instructions module.
  pub fn batch_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::Batch { .. }))
  }

  /// Create a transaction to execute a batch.
  pub fn execute_batch(batch: SignedBatch) -> Transaction {
    Transaction::Unsigned {
      call: UnsignedCall::try_from(serai_abi::Call::from(Call::execute_batch { batch }))
        .expect("`execute_batch` wasn't an unsigned call?"),
    }
  }
}
