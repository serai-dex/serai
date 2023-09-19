use std::io::Read;

use scale::{Encode, Decode};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use serai_client::validator_sets::primitives::{ValidatorSet, KeyPair};

pub use serai_db::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Topic {
  Dkg,
  Batch([u8; 32]),
  Sign([u8; 32]),
}

impl Topic {
  fn as_key(&self, genesis: [u8; 32]) -> Vec<u8> {
    match self {
      Topic::Dkg => [genesis.as_slice(), b"dkg".as_ref()].concat(),
      Topic::Batch(id) => [genesis.as_slice(), b"batch".as_ref(), id.as_ref()].concat(),
      Topic::Sign(id) => [genesis.as_slice(), b"sign".as_ref(), id.as_ref()].concat(),
    }
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
  fn as_key(&self, genesis: [u8; 32]) -> Vec<u8> {
    // TODO: Use a proper transcript here to avoid conflicts?
    [
      self.topic.as_key(genesis).as_ref(),
      self.label.as_bytes(),
      self.attempt.to_le_bytes().as_ref(),
    ]
    .concat()
  }
}

#[derive(Debug)]
pub struct TributaryDb<D: Db>(pub D);
impl<D: Db> TributaryDb<D> {
  pub fn new(db: D) -> Self {
    Self(db)
  }

  fn tributary_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"coordinator_tributary", dst, key)
  }

  // Last block scanned
  fn last_block_key(genesis: [u8; 32]) -> Vec<u8> {
    Self::tributary_key(b"block", genesis)
  }
  pub fn set_last_block(&mut self, genesis: [u8; 32], block: [u8; 32]) {
    let mut txn = self.0.txn();
    txn.put(Self::last_block_key(genesis), block);
    txn.commit();
  }
  pub fn last_block(&self, genesis: [u8; 32]) -> [u8; 32] {
    self
      .0
      .get(Self::last_block_key(genesis))
      .map(|last| last.try_into().unwrap())
      .unwrap_or(genesis)
  }

  // If a validator has been fatally slashed
  fn fatal_slash_key(genesis: [u8; 32]) -> Vec<u8> {
    Self::tributary_key(b"fatal_slash", genesis)
  }
  pub fn set_fatally_slashed(txn: &mut D::Transaction<'_>, genesis: [u8; 32], id: [u8; 32]) {
    let key = Self::fatal_slash_key(genesis);
    let mut existing = txn.get(&key).unwrap_or(vec![]);

    // Don't append if we already have it
    if existing.chunks(32).any(|ex_id| ex_id == id) {
      return;
    }

    existing.extend(id);
    txn.put(key, existing);
  }

  // The plan IDs associated with a Substrate block
  fn plan_ids_key(genesis: &[u8], block: u64) -> Vec<u8> {
    Self::tributary_key(b"plan_ids", [genesis, block.to_le_bytes().as_ref()].concat())
  }
  pub fn set_plan_ids(
    txn: &mut D::Transaction<'_>,
    genesis: [u8; 32],
    block: u64,
    plans: &[[u8; 32]],
  ) {
    txn.put(Self::plan_ids_key(&genesis, block), plans.concat());
  }
  pub fn plan_ids<G: Get>(getter: &G, genesis: [u8; 32], block: u64) -> Option<Vec<[u8; 32]>> {
    getter.get(Self::plan_ids_key(&genesis, block)).map(|bytes| {
      let mut res = vec![];
      let mut bytes_ref: &[u8] = bytes.as_ref();
      while !bytes_ref.is_empty() {
        let mut id = [0; 32];
        bytes_ref.read_exact(&mut id).unwrap();
        res.push(id);
      }
      res
    })
  }

  // The key pair which we're actively working on completing
  fn currently_completing_key_pair_key(genesis: [u8; 32]) -> Vec<u8> {
    Self::tributary_key(b"currently_completing_key_pair", genesis)
  }
  pub fn save_currently_completing_key_pair(
    txn: &mut D::Transaction<'_>,
    genesis: [u8; 32],
    key_pair: &KeyPair,
  ) {
    txn.put(Self::currently_completing_key_pair_key(genesis), key_pair.encode())
  }
  pub fn currently_completing_key_pair<G: Get>(getter: &G, genesis: [u8; 32]) -> Option<KeyPair> {
    getter
      .get(Self::currently_completing_key_pair_key(genesis))
      .map(|bytes| KeyPair::decode(&mut bytes.as_slice()).unwrap())
  }

  // The key pair confirmed for this Tributary
  pub fn key_pair_key(set: ValidatorSet) -> Vec<u8> {
    Self::tributary_key(b"key_pair", set.encode())
  }
  pub fn set_key_pair(txn: &mut D::Transaction<'_>, set: ValidatorSet, key_pair: &KeyPair) {
    txn.put(Self::key_pair_key(set), key_pair.encode());
  }
  pub fn key_pair<G: Get>(getter: &G, set: ValidatorSet) -> Option<KeyPair> {
    Some(KeyPair::decode(&mut getter.get(Self::key_pair_key(set))?.as_slice()).unwrap())
  }

  // The current attempt to resolve a topic
  fn attempt_key(genesis: [u8; 32], topic: Topic) -> Vec<u8> {
    Self::tributary_key(b"attempt", topic.as_key(genesis))
  }
  pub fn recognize_topic(txn: &mut D::Transaction<'_>, genesis: [u8; 32], topic: Topic) {
    txn.put(Self::attempt_key(genesis, topic), 0u32.to_le_bytes())
  }
  pub fn attempt<G: Get>(getter: &G, genesis: [u8; 32], topic: Topic) -> Option<u32> {
    let attempt_bytes = getter.get(Self::attempt_key(genesis, topic));
    // DKGs start when the chain starts
    if attempt_bytes.is_none() && (topic == Topic::Dkg) {
      return Some(0);
    }
    Some(u32::from_le_bytes(attempt_bytes?.try_into().unwrap()))
  }

  // Key for the amount of instances received thus far
  fn data_received_key(genesis: [u8; 32], data_spec: &DataSpecification) -> Vec<u8> {
    Self::tributary_key(b"data_received", data_spec.as_key(genesis))
  }
  // Key for an instance of data from a specific validator
  fn data_key(
    genesis: [u8; 32],
    data_spec: &DataSpecification,
    signer: <Ristretto as Ciphersuite>::G,
  ) -> Vec<u8> {
    Self::tributary_key(
      b"data",
      [data_spec.as_key(genesis).as_slice(), signer.to_bytes().as_ref()].concat(),
    )
  }
  pub fn data<G: Get>(
    getter: &G,
    genesis: [u8; 32],
    data_spec: &DataSpecification,
    signer: <Ristretto as Ciphersuite>::G,
  ) -> Option<Vec<u8>> {
    getter.get(Self::data_key(genesis, data_spec, signer))
  }
  pub fn set_data(
    txn: &mut D::Transaction<'_>,
    genesis: [u8; 32],
    data_spec: &DataSpecification,
    signer: <Ristretto as Ciphersuite>::G,
    data: &[u8],
  ) -> u16 {
    let received_key = Self::data_received_key(genesis, data_spec);
    let mut received =
      u16::from_le_bytes(txn.get(&received_key).unwrap_or(vec![0; 2]).try_into().unwrap());
    received += 1;

    txn.put(received_key, received.to_le_bytes());
    txn.put(Self::data_key(genesis, data_spec, signer), data);

    received
  }

  fn event_key(id: &[u8], index: u32) -> Vec<u8> {
    Self::tributary_key(b"event", [id, index.to_le_bytes().as_ref()].concat())
  }
  pub fn handled_event<G: Get>(getter: &G, id: [u8; 32], index: u32) -> bool {
    getter.get(Self::event_key(&id, index)).is_some()
  }
  pub fn handle_event(txn: &mut D::Transaction<'_>, id: [u8; 32], index: u32) {
    assert!(!Self::handled_event(txn, id, index));
    txn.put(Self::event_key(&id, index), []);
  }
}
