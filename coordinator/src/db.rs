use core::marker::PhantomData;

use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};

use scale::{Encode, Decode};
use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet},
  in_instructions::primitives::{Batch, SignedBatch},
};

pub use serai_db::*;

use ::tributary::ReadWrite;
use crate::tributary::{TributarySpec, Transaction, scanner::RecognizedIdType};

#[derive(Debug)]
pub struct MainDb<D: Db>(PhantomData<D>);
impl<D: Db> MainDb<D> {
  fn main_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"coordinator_main", dst, key)
  }

  fn handled_message_key(network: NetworkId, id: u64) -> Vec<u8> {
    Self::main_key(b"handled_message", (network, id).encode())
  }
  pub fn save_handled_message(txn: &mut D::Transaction<'_>, network: NetworkId, id: u64) {
    txn.put(Self::handled_message_key(network, id), []);
  }
  pub fn handled_message<G: Get>(getter: &G, network: NetworkId, id: u64) -> bool {
    getter.get(Self::handled_message_key(network, id)).is_some()
  }

  fn in_tributary_key(set: ValidatorSet) -> Vec<u8> {
    Self::main_key(b"in_tributary", set.encode())
  }
  fn active_tributaries_key() -> Vec<u8> {
    Self::main_key(b"active_tributaries", [])
  }
  fn retired_tributary_key(set: ValidatorSet) -> Vec<u8> {
    Self::main_key(b"retired_tributary", set.encode())
  }
  pub fn in_tributary<G: Get>(getter: &G, set: ValidatorSet) -> bool {
    getter.get(Self::in_tributary_key(set)).is_some()
  }
  pub fn active_tributaries<G: Get>(getter: &G) -> (Vec<u8>, Vec<TributarySpec>) {
    let bytes = getter.get(Self::active_tributaries_key()).unwrap_or(vec![]);
    let mut bytes_ref: &[u8] = bytes.as_ref();

    let mut tributaries = vec![];
    while !bytes_ref.is_empty() {
      tributaries.push(TributarySpec::read(&mut bytes_ref).unwrap());
    }

    (bytes, tributaries)
  }
  pub fn add_participating_in_tributary(txn: &mut D::Transaction<'_>, spec: &TributarySpec) {
    txn.put(Self::in_tributary_key(spec.set()), []);

    let key = Self::active_tributaries_key();
    let (mut existing_bytes, existing) = Self::active_tributaries(txn);
    for tributary in &existing {
      if tributary == spec {
        return;
      }
    }

    spec.write(&mut existing_bytes).unwrap();
    txn.put(key, existing_bytes);
  }
  pub fn retire_tributary(txn: &mut D::Transaction<'_>, set: ValidatorSet) {
    let mut active = Self::active_tributaries(txn).1;
    for i in 0 .. active.len() {
      if active[i].set() == set {
        active.remove(i);
        break;
      }
    }

    let mut bytes = vec![];
    for active in active {
      active.write(&mut bytes).unwrap();
    }
    txn.put(Self::active_tributaries_key(), bytes);
    txn.put(Self::retired_tributary_key(set), []);
  }
  pub fn is_tributary_retired<G: Get>(getter: &G, set: ValidatorSet) -> bool {
    getter.get(Self::retired_tributary_key(set)).is_some()
  }

  fn signed_transaction_key(nonce: u32) -> Vec<u8> {
    Self::main_key(b"signed_transaction", nonce.to_le_bytes())
  }
  pub fn save_signed_transaction(txn: &mut D::Transaction<'_>, nonce: u32, tx: Transaction) {
    txn.put(Self::signed_transaction_key(nonce), tx.serialize());
  }
  pub fn take_signed_transaction(txn: &mut D::Transaction<'_>, nonce: u32) -> Option<Transaction> {
    let key = Self::signed_transaction_key(nonce);
    let res = txn.get(&key).map(|bytes| Transaction::read(&mut bytes.as_slice()).unwrap());
    if res.is_some() {
      txn.del(&key);
    }
    res
  }

  fn first_preprocess_key(network: NetworkId, id_type: RecognizedIdType, id: &[u8]) -> Vec<u8> {
    Self::main_key(b"first_preprocess", (network, id_type, id).encode())
  }
  pub fn save_first_preprocess(
    txn: &mut D::Transaction<'_>,
    network: NetworkId,
    id_type: RecognizedIdType,
    id: &[u8],
    preprocess: Vec<Vec<u8>>,
  ) {
    let preprocess = preprocess.encode();
    let key = Self::first_preprocess_key(network, id_type, id);
    if let Some(existing) = txn.get(&key) {
      assert_eq!(existing, preprocess, "saved a distinct first preprocess");
      return;
    }
    txn.put(key, preprocess);
  }
  pub fn first_preprocess<G: Get>(
    getter: &G,
    network: NetworkId,
    id_type: RecognizedIdType,
    id: &[u8],
  ) -> Option<Vec<Vec<u8>>> {
    getter
      .get(Self::first_preprocess_key(network, id_type, id))
      .map(|bytes| Vec::<_>::decode(&mut bytes.as_slice()).unwrap())
  }

  fn last_received_batch_key(network: NetworkId) -> Vec<u8> {
    Self::main_key(b"last_received_batch", network.encode())
  }
  fn expected_batch_key(network: NetworkId, id: u32) -> Vec<u8> {
    Self::main_key(b"expected_batch", (network, id).encode())
  }
  pub fn save_expected_batch(txn: &mut D::Transaction<'_>, batch: &Batch) {
    txn.put(Self::last_received_batch_key(batch.network), batch.id.to_le_bytes());
    txn.put(
      Self::expected_batch_key(batch.network, batch.id),
      Blake2b::<U32>::digest(batch.instructions.encode()),
    );
  }
  pub fn last_received_batch<G: Get>(getter: &G, network: NetworkId) -> Option<u32> {
    getter
      .get(Self::last_received_batch_key(network))
      .map(|id| u32::from_le_bytes(id.try_into().unwrap()))
  }
  pub fn expected_batch<G: Get>(getter: &G, network: NetworkId, id: u32) -> Option<[u8; 32]> {
    getter.get(Self::expected_batch_key(network, id)).map(|batch| batch.try_into().unwrap())
  }

  fn batch_key(network: NetworkId, id: u32) -> Vec<u8> {
    Self::main_key(b"batch", (network, id).encode())
  }
  pub fn save_batch(txn: &mut D::Transaction<'_>, batch: SignedBatch) {
    txn.put(Self::batch_key(batch.batch.network, batch.batch.id), batch.encode());
  }
  pub fn batch<G: Get>(getter: &G, network: NetworkId, id: u32) -> Option<SignedBatch> {
    getter
      .get(Self::batch_key(network, id))
      .map(|batch| SignedBatch::decode(&mut batch.as_ref()).unwrap())
  }

  fn last_verified_batch_key(network: NetworkId) -> Vec<u8> {
    Self::main_key(b"last_verified_batch", network.encode())
  }
  pub fn save_last_verified_batch(txn: &mut D::Transaction<'_>, network: NetworkId, id: u32) {
    txn.put(Self::last_verified_batch_key(network), id.to_le_bytes());
  }
  pub fn last_verified_batch<G: Get>(getter: &G, network: NetworkId) -> Option<u32> {
    getter
      .get(Self::last_verified_batch_key(network))
      .map(|id| u32::from_le_bytes(id.try_into().unwrap()))
  }

  fn handover_batch_key(set: ValidatorSet) -> Vec<u8> {
    Self::main_key(b"handover_batch", set.encode())
  }
  fn lookup_handover_batch_key(network: NetworkId, batch: u32) -> Vec<u8> {
    Self::main_key(b"lookup_handover_batch", (network, batch).encode())
  }
  pub fn set_handover_batch(txn: &mut D::Transaction<'_>, set: ValidatorSet, batch: u32) {
    txn.put(Self::handover_batch_key(set), batch.to_le_bytes());
    txn.put(Self::lookup_handover_batch_key(set.network, batch), set.session.0.to_le_bytes());
  }
  pub fn handover_batch<G: Get>(getter: &G, set: ValidatorSet) -> Option<u32> {
    getter.get(Self::handover_batch_key(set)).map(|id| u32::from_le_bytes(id.try_into().unwrap()))
  }
  pub fn is_handover_batch<G: Get>(
    getter: &G,
    network: NetworkId,
    batch: u32,
  ) -> Option<ValidatorSet> {
    getter.get(Self::lookup_handover_batch_key(network, batch)).map(|session| ValidatorSet {
      network,
      session: Session(u32::from_le_bytes(session.try_into().unwrap())),
    })
  }

  fn queued_batches_key(set: ValidatorSet) -> Vec<u8> {
    Self::main_key(b"queued_batches", set.encode())
  }
  pub fn queue_batch(txn: &mut D::Transaction<'_>, set: ValidatorSet, batch: Transaction) {
    let key = Self::queued_batches_key(set);
    let mut batches = txn.get(&key).unwrap_or(vec![]);
    batches.extend(batch.serialize());
    txn.put(&key, batches);
  }
  pub fn take_queued_batches(txn: &mut D::Transaction<'_>, set: ValidatorSet) -> Vec<Transaction> {
    let key = Self::queued_batches_key(set);
    let batches_vec = txn.get(&key).unwrap_or(vec![]);
    txn.del(&key);
    let mut batches: &[u8] = &batches_vec;

    let mut res = vec![];
    while !batches.is_empty() {
      res.push(Transaction::read(&mut batches).unwrap());
    }
    res
  }
}
