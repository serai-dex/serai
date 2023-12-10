use core::ops::Deref;
use std::collections::HashMap;

use zeroize::Zeroizing;
use ciphersuite::{Ciphersuite, Ristretto, group::GroupEncoding};
use frost::Participant;

use serai_client::validator_sets::primitives::KeyPair;

use processor_messages::coordinator::SubstrateSignableId;

use scale::{Encode, Decode};

pub use serai_db::*;

use crate::tributary::TributarySpec;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode)]
pub enum Topic {
  Dkg,
  DkgRemoval([u8; 32]),
  SubstrateSign(SubstrateSignableId),
  Sign([u8; 32]),
}

// A struct to refer to a piece of data all validators will presumably provide a value for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode)]
pub struct DataSpecification {
  pub topic: Topic,
  pub label: &'static str,
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
    LastBlock: (genesis: [u8; 32]) -> [u8; 32],
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
    if attempt.is_none() && (topic == Topic::Dkg) {
      return Some(0);
    }
    attempt
  }
}

impl DataDb {
  pub fn accumulate(
    txn: &mut impl DbTxn,
    our_key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    spec: &TributarySpec,
    data_spec: &DataSpecification,
    signer: <Ristretto as Ciphersuite>::G,
    data: &Vec<u8>,
  ) -> Accumulation {
    let genesis = spec.genesis();
    if Self::get(txn, genesis, data_spec, &signer.to_bytes()).is_some() {
      panic!("accumulating data for a participant multiple times");
    }
    let signer_shares = {
      let signer_i =
        spec.i(signer).expect("transaction signed by a non-validator for this tributary");
      u16::from(signer_i.end) - u16::from(signer_i.start)
    };

    let prior_received = DataReceived::get(txn, genesis, data_spec).unwrap_or_default();
    let now_received = prior_received + signer_shares;
    DataReceived::set(txn, genesis, data_spec, &now_received);
    DataDb::set(txn, genesis, data_spec, &signer.to_bytes(), data);

    // If we have all the needed commitments/preprocesses/shares, tell the processor
    let needed = if data_spec.topic == Topic::Dkg { spec.n() } else { spec.t() };
    if (prior_received < needed) && (now_received >= needed) {
      return Accumulation::Ready({
        let mut data = HashMap::new();
        for validator in spec.validators().iter().map(|validator| validator.0) {
          data.insert(
            spec.i(validator).unwrap().start,
            if let Some(data) = Self::get(txn, genesis, data_spec, &validator.to_bytes()) {
              data
            } else {
              continue;
            },
          );
        }

        assert_eq!(data.len(), usize::from(needed));

        // Remove our own piece of data, if we were involved
        if data
          .remove(
            &spec
              .i(Ristretto::generator() * our_key.deref())
              .expect("handling a message for a Tributary we aren't part of")
              .start,
          )
          .is_some()
        {
          DataSet::Participating(data)
        } else {
          DataSet::NotParticipating
        }
      });
    }
    Accumulation::NotReady
  }
}
