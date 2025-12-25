use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  BitVec, BlockHash, network_id::ExternalNetworkId, validator_sets::Session, address::SeraiAddress,
  instructions::SignedBatch,
};

/// The address used for executing `InInstruction`s.
pub fn address() -> SeraiAddress {
  SeraiAddress::system(borsh::to_vec(b"InInstructions").unwrap())
}

/// A call to the `InInstruction`s' module.
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

// This is the smallest bound with a 4-byte length prefix.
const IN_INSTRUCTION_RESULTS_BOUND: u64 = (u16::MAX as u64) + 1;

/// An event from the `InInstruction`s module.
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
    in_instruction_results: BitVec<{ IN_INSTRUCTION_RESULTS_BOUND }>,
  },
}

#[test]
fn in_instruction_results_bound() {
  use alloc::vec;

  /*
    We picked a bound high enough the `in_instruction_results` vector will have the same
    length-prefix length as the `instructions` vector within the `Batch`, ensuring they have
    parity. Here, we ensure the bound isn't too low on the assumption each instruction takes at
    least one byte to encode.
  */
  assert!(IN_INSTRUCTION_RESULTS_BOUND >= (serai_primitives::prelude::Batch::MAX_SIZE as u64));

  // Confirm this bound causes a 4-byte length prefix
  {
    // Technically, this assumes `BoundedVec` and `BitVec` apply the same length-prefixing
    // policy, but that is how the Serai protocol is defined
    use sp_core::{ConstU32, bounded::BoundedVec};
    let mut bounded_vec_encoding = vec![];
    #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
    serai_primitives::sp_borsh::borsh_serialize_bounded_vec(
      &BoundedVec::<u8, ConstU32<{ IN_INSTRUCTION_RESULTS_BOUND as u32 }>>::new(),
      &mut bounded_vec_encoding,
    )
    .unwrap();
    assert_eq!(bounded_vec_encoding, vec![0, 0, 0, 0]);
  }

  // Confirm a standard `Vec`, as seen inside the `Batch`, will also have a 4-byte length prefix
  assert_eq!(borsh::to_vec(&vec![0xffu8]).unwrap(), vec![1, 0, 0, 0, 0xff]);
}
