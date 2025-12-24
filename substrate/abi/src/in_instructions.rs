use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  BitVec, BlockHash,
  network_id::ExternalNetworkId,
  validator_sets::Session,
  address::SeraiAddress,
  instructions::{Batch, SignedBatch},
};

/// The address used for executing `InInstruction`s.
pub fn address() -> SeraiAddress {
  SeraiAddress::system(borsh::to_vec(b"InInstructions").unwrap())
}

/// A call to `InInstruction`s.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Call {
  /// Execute a batch of `InInstruction`s.
  execute_batch {
    /// The batch to execute.
    batch: SignedBatch,
  },
}

impl Call {
  pub(crate) fn is_signed(&self) -> bool {
    match self {
      Call::execute_batch { .. } => false,
    }
  }
}

/// An event from `InInstruction`s.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// A batch of `InInstruction`s was executed.
  Batch {
    /// The network for which a batch was executed.
    network: ExternalNetworkId,
    /// The session which published the batch.
    publishing_session: Session,
    /// The ID of the batch.
    id: u32,
    /// The hash of the block on the external network which caused this batch's creation.
    external_network_block_hash: BlockHash,
    /// The hash of the `InInstruction`s within this batch.
    in_instructions_hash: [u8; 32],
    /// The results of each `InInstruction` within the batch.
    // We are able to assume each `InInstruction` takes at least one byte to encode, setting a
    // maximum amount of `InInstruction`s as the maximum size of the `Batch`.
    in_instruction_results: BitVec<{ Batch::MAX_SIZE as u64 }>,
  },
}
