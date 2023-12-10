use std::collections::HashMap;

use frost::Participant;

use serai_client::validator_sets::primitives::KeyPair;

use processor_messages::coordinator::SubstrateSignableId;

use scale::Encode;

pub use serai_db::*;

use crate::tributary::Label;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode)]
pub enum Topic {
  Dkg,
  DkgConfirmation,
  DkgRemoval([u8; 32]),
  SubstrateSign(SubstrateSignableId),
  Sign([u8; 32]),
}

// A struct to refer to a piece of data all validators will presumably provide a value for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode)]
pub struct DataSpecification {
  pub topic: Topic,
  pub label: Label,
  pub attempt: u32,
}

pub enum DataSet {
  Participating(HashMap<Participant, Vec<u8>>),
  NotParticipating,
}

pub enum Accumulation {
  Ready(DataSet),
  NotReady,
}

create_db!(
  Tributary {
    SeraiBlockNumber: (hash: [u8; 32]) -> u64,
    LastHandledBlock: (genesis: [u8; 32]) -> [u8; 32],
    FatalSlashes: (genesis: [u8; 32]) -> Vec<[u8; 32]>,
    FatallySlashed: (genesis: [u8; 32], account: [u8; 32]) -> (),
    DkgShare: (genesis: [u8; 32], from: u16, to: u16) -> Vec<u8>,
    PlanIds: (genesis: &[u8], block: u64) -> Vec<[u8; 32]>,
    ConfirmationNonces: (genesis: [u8; 32], attempt: u32) -> HashMap<Participant, Vec<u8>>,
    RemovalNonces:
      (genesis: [u8; 32], removing: [u8; 32], attempt: u32) -> HashMap<Participant, Vec<u8>>,
    CurrentlyCompletingKeyPair: (genesis: [u8; 32]) -> KeyPair,
    DkgCompleted: (genesis: [u8; 32]) -> (),
    AttemptDb: (genesis: [u8; 32], topic: &Topic) -> u32,
    DataReceived: (genesis: [u8; 32], data_spec: &DataSpecification) -> u16,
    DataDb: (genesis: [u8; 32], data_spec: &DataSpecification, signer_bytes: &[u8; 32]) -> Vec<u8>,
  }
);

impl FatallySlashed {
  pub fn set_fatally_slashed(txn: &mut impl DbTxn, genesis: [u8; 32], account: [u8; 32]) {
    Self::set(txn, genesis, account, &());
    let mut existing = FatalSlashes::get(txn, genesis).unwrap_or_default();

    // Don't append if we already have it
    if existing.iter().any(|existing| existing == &account) {
      return;
    }

    existing.push(account);
    FatalSlashes::set(txn, genesis, &existing);
  }
}

impl AttemptDb {
  pub fn recognize_topic(txn: &mut impl DbTxn, genesis: [u8; 32], topic: Topic) {
    Self::set(txn, genesis, &topic, &0u32);
  }

  pub fn attempt(getter: &impl Get, genesis: [u8; 32], topic: Topic) -> Option<u32> {
    let attempt = Self::get(getter, genesis, &topic);
    // Don't require explicit recognition of the Dkg topic as it starts when the chain does
    if attempt.is_none() && ((topic == Topic::Dkg) || (topic == Topic::DkgConfirmation)) {
      return Some(0);
    }
    attempt
  }
}
