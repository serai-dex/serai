//! [`serai_abi::Event`] constructor helpers

use serai_abi::{
  primitives::{address::SeraiAddress, balance::Amount},
  Event,
};

/// Event constructors for [`Event::ValidatorSets`] types.
pub mod validator_sets {
  use super::*;
  use serai_abi::validator_sets::Event as ValidatorSetsEvent;
  use serai_primitives::{
    network_id::NetworkId,
    validator_sets::{self, ExternalValidatorSet},
  };

  /// Creates a [`Event::ValidatorSets(SetDecided)`] event for a decided validator set.
  pub fn set_decided(
    set: validator_sets::ValidatorSet,
    validators: Vec<(SeraiAddress, validator_sets::KeyShares)>,
  ) -> Event {
    Event::ValidatorSets(ValidatorSetsEvent::SetDecided { set, validators })
  }

  /// Creates an [`Event::ValidatorSets(Allocation)`] event for a new allocation.
  pub fn allocation(validator: SeraiAddress, network: NetworkId, amount: u64) -> Event {
    Event::ValidatorSets(ValidatorSetsEvent::Allocation {
      validator,
      network,
      amount: Amount(amount),
    })
  }

  /// Creates a [`Event::ValidatorSets(Deallocation)`] event with an immediate timeline.
  pub fn deallocation(validator: SeraiAddress, network: NetworkId, amount: u64) -> Event {
    Event::ValidatorSets(ValidatorSetsEvent::Deallocation {
      validator,
      network,
      amount: Amount(amount),
      timeline: validator_sets::DeallocationTimeline::Immediate,
    })
  }

  /// Creates a [`Event::ValidatorSets(Slashes)`] event for an external validator set.
  pub fn slash_report(set: ExternalValidatorSet) -> Event {
    Event::ValidatorSets(ValidatorSetsEvent::Slashes(
      serai_abi::validator_sets::ReportedSlashes::ExternalValidatorSet(set),
    ))
  }

  /// Creates a [`Event::ValidatorSets(SetKeys)`] event for a validator set key pair.
  pub fn set_keys(set: ExternalValidatorSet, key_pair: serai_primitives::crypto::KeyPair) -> Event {
    Event::ValidatorSets(ValidatorSetsEvent::SetKeys { set, key_pair })
  }

  /// Creates a [`Event::ValidatorSets(SetEmbeddedEllipticCurveKeys)`] event.
  pub fn set_embedded_elliptic_curve_keys(
    validator: SeraiAddress,
    keys: serai_primitives::crypto::EmbeddedEllipticCurveKeys,
  ) -> Event {
    Event::ValidatorSets(ValidatorSetsEvent::SetEmbeddedEllipticCurveKeys { validator, keys })
  }
}

/// Event constructors for [`Event::Coins`] types.
pub mod coins {
  use super::*;

  /// Creates a [`Event::Coins(BurnWithInstruction)`] event transferring to an external addr.
  pub fn burn_with_instruction(
    from: SeraiAddress,
    to: serai_primitives::address::ExternalAddress,
    amount: u64,
  ) -> Event {
    Event::Coins(serai_abi::coins::Event::BurnWithInstruction {
      from,
      instruction: serai_primitives::instructions::OutInstructionWithBalance {
        instruction: serai_primitives::instructions::OutInstruction::Transfer(to),
        balance: serai_primitives::balance::ExternalBalance {
          coin: serai_primitives::coin::ExternalCoin::Bitcoin,
          amount: Amount(amount),
        },
      },
    })
  }
}

/// Event constructors for [`Event::InInstructions`] types.
pub mod in_instructions {
  use super::*;

  /// Creates a a random [`Event::InInstructions(Batch)`] event.
  pub fn batch(
    network: serai_primitives::network_id::ExternalNetworkId,
    publishing_session: serai_primitives::validator_sets::Session,
    id: u32,
    external_network_block_hash: serai_primitives::BlockHash,
    in_instructions_hash: [u8; 32],
    in_instruction_results: serai_primitives::BitVec<
      { serai_abi::in_instructions::IN_INSTRUCTION_RESULTS_BOUND },
    >,
  ) -> Event {
    Event::InInstructions(serai_abi::in_instructions::Event::Batch {
      network,
      publishing_session,
      id,
      external_network_block_hash,
      in_instructions_hash,
      in_instruction_results,
    })
  }
}
