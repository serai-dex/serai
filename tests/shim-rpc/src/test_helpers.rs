//! Test helper functions for constructing common Serai ABI events.

use serai_abi::{
  primitives::{
    address::*, network_id::*, coin::*, balance::*, validator_sets::*, instructions::*,
  },
  *,
};

pub fn set_decided_event(set: ValidatorSet, validators: Vec<(SeraiAddress, KeyShares)>) -> Event {
  Event::ValidatorSets(validator_sets::Event::SetDecided { set, validators })
}

pub fn allocation_event(validator: SeraiAddress, network: NetworkId, amount: u64) -> Event {
  Event::ValidatorSets(validator_sets::Event::Allocation {
    validator,
    network,
    amount: Amount(amount),
  })
}

pub fn deallocation_event(validator: SeraiAddress, network: NetworkId, amount: u64) -> Event {
  Event::ValidatorSets(validator_sets::Event::Deallocation {
    validator,
    network,
    amount: Amount(amount),
    timeline: DeallocationTimeline::Immediate,
  })
}

pub fn burn_with_instruction_event(from: SeraiAddress, to: ExternalAddress, amount: u64) -> Event {
  Event::Coins(coins::Event::BurnWithInstruction {
    from,
    instruction: OutInstructionWithBalance {
      instruction: OutInstruction::Transfer(to),
      balance: ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(amount) },
    },
  })
}
