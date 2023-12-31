use std::collections::HashMap;

use scale::Encode;
use borsh::{BorshSerialize, BorshDeserialize};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::Participant;

use serai_client::validator_sets::primitives::{KeyPair, ValidatorSet};

use processor_messages::coordinator::SubstrateSignableId;

pub use serai_db::*;

use tributary::ReadWrite;

use crate::tributary::{Label, Transaction};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, BorshSerialize, BorshDeserialize)]
pub enum Topic {
  Dkg,
  DkgConfirmation,
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

// TODO: Move from genesis to set for indexing
create_db!(
  Tributary {
    SeraiBlockNumber: (hash: [u8; 32]) -> u64,
    SeraiDkgCompleted: (spec: ValidatorSet) -> [u8; 32],

    TributaryBlockNumber: (block: [u8; 32]) -> u32,
    LastHandledBlock: (genesis: [u8; 32]) -> [u8; 32],

    FatalSlashes: (genesis: [u8; 32]) -> Vec<[u8; 32]>,
    RemovedAsOfDkgAttempt: (genesis: [u8; 32], attempt: u32) -> Vec<[u8; 32]>,
    OfflineDuringDkg: (genesis: [u8; 32]) -> Vec<[u8; 32]>,
    FatallySlashed: (genesis: [u8; 32], account: [u8; 32]) -> (),

    VotedToRemove: (genesis: [u8; 32], voter: [u8; 32], to_remove: [u8; 32]) -> (),
    VotesToRemove: (genesis: [u8; 32], to_remove: [u8; 32]) -> u16,

    AttemptDb: (genesis: [u8; 32], topic: &Topic) -> u32,
    ReattemptDb: (genesis: [u8; 32], block: u32) -> Vec<Topic>,
    DataReceived: (genesis: [u8; 32], data_spec: &DataSpecification) -> u16,
    DataDb: (genesis: [u8; 32], data_spec: &DataSpecification, signer_bytes: &[u8; 32]) -> Vec<u8>,

    DkgShare: (genesis: [u8; 32], from: u16, to: u16) -> Vec<u8>,
    ConfirmationNonces: (genesis: [u8; 32], attempt: u32) -> HashMap<Participant, Vec<u8>>,
    DkgKeyPair: (genesis: [u8; 32], attempt: u32) -> KeyPair,
    KeyToDkgAttempt: (key: [u8; 32]) -> u32,
    DkgLocallyCompleted: (genesis: [u8; 32]) -> (),

    PlanIds: (genesis: &[u8], block: u64) -> Vec<[u8; 32]>,

    SignedTransactionDb: (order: &[u8], nonce: u32) -> Vec<u8>,
  }
);

impl FatalSlashes {
  pub fn get_as_keys(getter: &impl Get, genesis: [u8; 32]) -> Vec<<Ristretto as Ciphersuite>::G> {
    FatalSlashes::get(getter, genesis)
      .unwrap_or(vec![])
      .iter()
      .map(|key| <Ristretto as Ciphersuite>::G::from_bytes(key).unwrap())
      .collect::<Vec<_>>()
  }
}

impl FatallySlashed {
  pub fn set_fatally_slashed(txn: &mut impl DbTxn, genesis: [u8; 32], account: [u8; 32]) {
    Self::set(txn, genesis, account, &());
    let mut existing = FatalSlashes::get(txn, genesis).unwrap_or_default();

    // Don't append if we already have it, which can occur upon multiple faults
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

  pub fn start_next_attempt(txn: &mut impl DbTxn, genesis: [u8; 32], topic: Topic) -> u32 {
    let next =
      Self::attempt(txn, genesis, topic).expect("starting next attempt for unknown topic") + 1;
    Self::set(txn, genesis, &topic, &next);
    next
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

impl ReattemptDb {
  pub fn schedule_reattempt(
    txn: &mut impl DbTxn,
    genesis: [u8; 32],
    current_block_number: u32,
    topic: Topic,
  ) {
    // 5 minutes
    #[cfg(not(feature = "longer-reattempts"))]
    const BASE_REATTEMPT_DELAY: u32 = (5 * 60 * 1000) / tributary::tendermint::TARGET_BLOCK_TIME;

    // 10 minutes, intended for latent environments like the GitHub CI
    #[cfg(feature = "longer-reattempts")]
    const BASE_REATTEMPT_DELAY: u32 = (10 * 60 * 1000) / tributary::tendermint::TARGET_BLOCK_TIME;

    // 5 minutes for attempts 0 ..= 2, 10 minutes for attempts 3 ..= 5, 15 minutes for attempts > 5
    // Assumes no event will take longer than 15 minutes, yet grows the time in case there are
    // network bandwidth issues
    let reattempt_delay = BASE_REATTEMPT_DELAY *
      ((AttemptDb::attempt(txn, genesis, topic)
        .expect("scheduling re-attempt for unknown topic") /
        3) +
        1)
      .min(3);
    let upon_block = current_block_number + reattempt_delay;

    let mut reattempts = Self::get(txn, genesis, upon_block).unwrap_or(vec![]);
    reattempts.push(topic);
    Self::set(txn, genesis, upon_block, &reattempts);
  }

  pub fn take(txn: &mut impl DbTxn, genesis: [u8; 32], block_number: u32) -> Vec<Topic> {
    let res = Self::get(txn, genesis, block_number).unwrap_or(vec![]);
    if !res.is_empty() {
      Self::del(txn, genesis, block_number);
    }
    res
  }
}

impl SignedTransactionDb {
  pub fn take_signed_transaction(
    txn: &mut impl DbTxn,
    order: &[u8],
    nonce: u32,
  ) -> Option<Transaction> {
    let res = SignedTransactionDb::get(txn, order, nonce)
      .map(|bytes| Transaction::read(&mut bytes.as_slice()).unwrap());
    if res.is_some() {
      Self::del(txn, order, nonce);
    }
    res
  }
}
