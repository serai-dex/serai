use core::ops::Deref;
use std::collections::HashMap;

use zeroize::Zeroizing;
use ciphersuite::{Ciphersuite, Ristretto, group::GroupEncoding};
use frost::Participant;

use serai_client::validator_sets::primitives::{ValidatorSet, KeyPair};

use processor_messages::coordinator::SubstrateSignableId;

use scale::Encode;

pub use serai_db::*;

use crate::tributary::TributarySpec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Topic {
  Dkg,
  SubstrateSign(SubstrateSignableId),
  Sign([u8; 32]),
}

impl Topic {
  fn as_key(&self, genesis: [u8; 32]) -> Vec<u8> {
    let mut res = genesis.to_vec();
    #[allow(unused_assignments)] // False positive
    let mut id_buf = vec![];
    let (label, id) = match self {
      Topic::Dkg => (b"dkg".as_slice(), [].as_slice()),
      Topic::SubstrateSign(id) => {
        id_buf = id.encode();
        (b"substrate_sign".as_slice(), id_buf.as_slice())
      }
      Topic::Sign(id) => (b"sign".as_slice(), id.as_slice()),
    };
    res.push(u8::try_from(label.len()).unwrap());
    res.extend(label);
    res.push(u8::try_from(id.len()).unwrap());
    res.extend(id);
    res
  }
}

// A struct to refer to a piece of data all validators will presumably provide a value for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DataSpecification {
  pub topic: Topic,
  pub label: &'static str,
  pub attempt: u32,
}

impl DataSpecification {
  pub fn as_key(&self, genesis: [u8; 32]) -> Vec<u8> {
    let mut res = self.topic.as_key(genesis);
    let label_bytes = self.label.bytes();
    res.push(u8::try_from(label_bytes.len()).unwrap());
    res.extend(label_bytes);
    res.extend(self.attempt.to_le_bytes());
    res
  }
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
  NewTributary {
    SeraiBlockNumber: (hash: [u8; 32]) -> u64,
    LastBlock: (genesis: [u8; 32]) -> [u8; 32],
    FatalSlashes: (genesis: [u8; 32]) -> Vec<u8>,
    FatallySlashed: (genesis: [u8; 32], account: [u8; 32]) -> (),
    ShareBlame: (genesis: [u8; 32], from: u16, to: u16) -> Vec<u8>,
    PlanIds: (genesis: &[u8], block: u64) -> Vec<[u8; 32]>,
    ConfirmationNonces: (genesis: [u8; 32], attempt: u32) -> HashMap<Participant, Vec<u8>>,
    CurrentlyCompletingKeyPair: (genesis: [u8; 32]) -> KeyPair,
    KeyPairDb: (set: ValidatorSet) -> KeyPair,
    AttemptDb: (genesis: [u8; 32], topic_key: &Vec<u8>) -> u32,
    DataReceived: (genesis: [u8; 32], data_spec_key: &Vec<u8>) -> u16,
    DataDb: (genesis: [u8; 32], data_spec_key: &Vec<u8>, signer_bytes: &[u8; 32]) -> Vec<u8>,
    EventDb: (id: [u8; 32], index: u32) -> (),
  }
);

impl FatallySlashed {
  pub fn set_fatally_slashed(txn: &mut impl DbTxn, genesis: [u8; 32], account: [u8; 32]) {
    Self::set(txn, genesis, account, &());
    let mut existing = FatalSlashes::get(txn, genesis).unwrap_or_default();

    // Don't append if we already have it
    if existing.chunks(32).any(|existing| existing == account) {
      return;
    }

    existing.extend(account);
    FatalSlashes::set(txn, genesis, &existing);
  }
}

impl AttemptDb {
  pub fn recognize_topic(txn: &mut impl DbTxn, genesis: [u8; 32], topic: Topic) {
    Self::set(txn, genesis, &topic.as_key(genesis), &0u32);
  }

  pub fn attempt(getter: &impl Get, genesis: [u8; 32], topic: Topic) -> Option<u32> {
    let attempt = Self::get(getter, genesis, &topic.as_key(genesis));
    if attempt.is_none() && topic == Topic::Dkg {
      return Some(0);
    }
    attempt
  }
}

impl DataDb {
  pub fn set_data(
    txn: &mut impl DbTxn,
    genesis: [u8; 32],
    data_spec: &DataSpecification,
    signer: <Ristretto as Ciphersuite>::G,
    signer_shares: u16,
    data: &Vec<u8>,
  ) -> (u16, u16) {
    let data_spec = data_spec.as_key(genesis);
    let prior_received = DataReceived::get(txn, genesis, &data_spec).unwrap_or_default();
    let received = prior_received + signer_shares;
    DataReceived::set(txn, genesis, &data_spec, &received);
    DataDb::set(txn, genesis, &data_spec, &signer.to_bytes(), data);
    (prior_received, received)
  }

  pub fn accumulate(
    txn: &mut impl DbTxn,
    our_key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    spec: &TributarySpec,
    data_spec: &DataSpecification,
    signer: <Ristretto as Ciphersuite>::G,
    data: &Vec<u8>,
  ) -> Accumulation {
    let genesis = spec.genesis();
    let data_spec_key = data_spec.as_key(genesis);
    if Self::get(txn, genesis, &data_spec_key, &signer.to_bytes()).is_some() {
      panic!("accumulating data for a participant multiple times");
    }
    let signer_shares = {
      let signer_i =
        spec.i(signer).expect("transaction signed by a non-validator for this tributary");
      u16::from(signer_i.end) - u16::from(signer_i.start)
    };
    let (prior_received, now_received) =
      Self::set_data(txn, spec.genesis(), data_spec, signer, signer_shares, data);

    // If we have all the needed commitments/preprocesses/shares, tell the processor
    let needed = if data_spec.topic == Topic::Dkg { spec.n() } else { spec.t() };
    if (prior_received < needed) && (now_received >= needed) {
      return Accumulation::Ready({
        let mut data = HashMap::new();
        for validator in spec.validators().iter().map(|validator| validator.0) {
          data.insert(
            spec.i(validator).unwrap().start,
            if let Some(data) = Self::get(txn, genesis, &data_spec_key, &validator.to_bytes()) {
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

impl EventDb {
  pub fn handle_event(txn: &mut impl DbTxn, id: [u8; 32], index: u32) {
    assert!(Self::get(txn, id, index).is_none());
    Self::set(txn, id, index, &());
  }
}
