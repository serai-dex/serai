use core::{marker::PhantomData, ops::Deref};
use std::{io::Read, collections::HashMap};

use scale::{Encode, Decode};

use zeroize::Zeroizing;
use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::Participant;

use serai_client::validator_sets::primitives::{ValidatorSet, KeyPair};

pub use serai_db::*;

use crate::tributary::TributarySpec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Topic {
  Dkg,
  Batch([u8; 32]),
  Sign([u8; 32]),
}

impl Topic {
  fn as_key(&self, genesis: [u8; 32]) -> Vec<u8> {
    let mut res = genesis.to_vec();
    let (label, id) = match self {
      Topic::Dkg => (b"dkg".as_slice(), [].as_slice()),
      Topic::Batch(id) => (b"batch".as_slice(), id.as_slice()),
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
  fn as_key(&self, genesis: [u8; 32]) -> Vec<u8> {
    let mut res = self.topic.as_key(genesis);
    let label_bytes = self.label.bytes();
    res.push(u8::try_from(label_bytes.len()).unwrap());
    res.extend(label_bytes);
    res.extend(self.attempt.to_le_bytes());
    res
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
  fn fatal_slashes_key(genesis: [u8; 32]) -> Vec<u8> {
    Self::tributary_key(b"fatal_slashes", genesis)
  }
  fn fatally_slashed_key(account: [u8; 32]) -> Vec<u8> {
    Self::tributary_key(b"fatally_slashed", account)
  }
  pub fn set_fatally_slashed(txn: &mut D::Transaction<'_>, genesis: [u8; 32], account: [u8; 32]) {
    txn.put(Self::fatally_slashed_key(account), []);

    let key = Self::fatal_slashes_key(genesis);
    let mut existing = txn.get(&key).unwrap_or(vec![]);

    // Don't append if we already have it
    if existing.chunks(32).any(|existing| existing == account) {
      return;
    }

    existing.extend(account);
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

  fn confirmation_nonces_key(genesis: [u8; 32], attempt: u32) -> Vec<u8> {
    Self::tributary_key(b"confirmation_nonces", (genesis, attempt).encode())
  }
  pub fn save_confirmation_nonces(
    txn: &mut D::Transaction<'_>,
    genesis: [u8; 32],
    attempt: u32,
    nonces: HashMap<Participant, Vec<u8>>,
  ) {
    let nonces =
      nonces.into_iter().map(|(key, value)| (u16::from(key), value)).collect::<HashMap<_, _>>();
    txn.put(Self::confirmation_nonces_key(genesis, attempt), bincode::serialize(&nonces).unwrap())
  }
  pub fn confirmation_nonces<G: Get>(
    getter: &G,
    genesis: [u8; 32],
    attempt: u32,
  ) -> Option<HashMap<Participant, Vec<u8>>> {
    let bytes = getter.get(Self::confirmation_nonces_key(genesis, attempt))?;
    let map: HashMap<u16, Vec<u8>> = bincode::deserialize(&bytes).unwrap();
    Some(map.into_iter().map(|(key, value)| (Participant::new(key).unwrap(), value)).collect())
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

pub enum DataSet {
  Participating(HashMap<Participant, Vec<u8>>),
  NotParticipating,
}

pub enum Accumulation {
  Ready(DataSet),
  NotReady,
}

pub struct TributaryState<D: Db>(PhantomData<D>);
impl<D: Db> TributaryState<D> {
  pub fn accumulate(
    txn: &mut D::Transaction<'_>,
    our_key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    spec: &TributarySpec,
    data_spec: &DataSpecification,
    signer: <Ristretto as Ciphersuite>::G,
    data: &[u8],
  ) -> Accumulation {
    if TributaryDb::<D>::data(txn, spec.genesis(), data_spec, signer).is_some() {
      panic!("accumulating data for a participant multiple times");
    }
    let received = TributaryDb::<D>::set_data(txn, spec.genesis(), data_spec, signer, data);

    // If we have all the needed commitments/preprocesses/shares, tell the processor
    // TODO: This needs to be coded by weight, not by validator count
    let needed = if data_spec.topic == Topic::Dkg { spec.n() } else { spec.t() };
    if received == needed {
      return Accumulation::Ready({
        let mut data = HashMap::new();
        for validator in spec.validators().iter().map(|validator| validator.0) {
          data.insert(
            spec.i(validator).unwrap(),
            if let Some(data) = TributaryDb::<D>::data(txn, spec.genesis(), data_spec, validator) {
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
              .expect("handling a message for a Tributary we aren't part of"),
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
