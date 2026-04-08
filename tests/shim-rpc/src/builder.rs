use serai_abi::Event;

use crate::{state::ShimState, SeraiShimRpc};

/// Builder for constructing a [`SeraiShimRpc`] with pre-populated blocks.
#[must_use]
pub struct SeraiShimRpcBuilder {
  blocks: Vec<Vec<Vec<Event>>>,
}

impl SeraiShimRpcBuilder {
  /// Create a new builder.
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    Self { blocks: Vec::new() }
  }

  /// Add a single block with the given events (one `Vec<Event>` per transaction).
  pub fn with_block(mut self, events: Vec<Vec<Event>>) -> Self {
    self.blocks.push(events);
    self
  }

  /// Add multiple blocks, each with their own events.
  pub fn with_blocks(mut self, blocks: Vec<Vec<Vec<Event>>>) -> Self {
    self.blocks.extend(blocks);
    self
  }

  /// Build and start the shim RPC node.
  pub async fn build(self) -> SeraiShimRpc {
    let mut shim_state = ShimState::default();
    for (i, events) in self.blocks.into_iter().enumerate() {
      let number = u64::try_from(i).unwrap() + 1;
      shim_state.make_block(number, events);
    }

    SeraiShimRpc::start(shim_state).await
  }
}
