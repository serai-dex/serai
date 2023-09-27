use core::marker::PhantomData;

use scale::{Encode, Decode};
use serai_client::{primitives::NetworkId, in_instructions::primitives::SignedBatch};

pub use serai_db::*;

use ::tributary::ReadWrite;
use crate::tributary::{TributarySpec, Transaction};

#[derive(Debug)]
pub struct MainDb<D: Db>(PhantomData<D>);
impl<D: Db> MainDb<D> {
  fn main_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"coordinator_main", dst, key)
  }

  fn handled_message_key(id: u64) -> Vec<u8> {
    Self::main_key(b"handled_message", id.to_le_bytes())
  }
  pub fn save_handled_message(txn: &mut D::Transaction<'_>, id: u64) {
    txn.put(Self::handled_message_key(id), []);
  }
  pub fn handled_message<G: Get>(getter: &G, id: u64) -> bool {
    getter.get(Self::handled_message_key(id)).is_some()
  }

  fn acive_tributaries_key() -> Vec<u8> {
    Self::main_key(b"active_tributaries", [])
  }
  pub fn active_tributaries<G: Get>(getter: &G) -> (Vec<u8>, Vec<TributarySpec>) {
    let bytes = getter.get(Self::acive_tributaries_key()).unwrap_or(vec![]);
    let mut bytes_ref: &[u8] = bytes.as_ref();

    let mut tributaries = vec![];
    while !bytes_ref.is_empty() {
      tributaries.push(TributarySpec::read(&mut bytes_ref).unwrap());
    }

    (bytes, tributaries)
  }
  pub fn add_active_tributary(txn: &mut D::Transaction<'_>, spec: &TributarySpec) {
    let key = Self::acive_tributaries_key();
    let (mut existing_bytes, existing) = Self::active_tributaries(txn);
    for tributary in &existing {
      if tributary == spec {
        return;
      }
    }

    spec.write(&mut existing_bytes).unwrap();
    txn.put(key, existing_bytes);
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

  fn first_preprocess_key(id: [u8; 32]) -> Vec<u8> {
    Self::main_key(b"first_preprocess", id)
  }
  pub fn save_first_preprocess(txn: &mut D::Transaction<'_>, id: [u8; 32], preprocess: Vec<u8>) {
    let key = Self::first_preprocess_key(id);
    if let Some(existing) = txn.get(&key) {
      assert_eq!(existing, preprocess, "saved a distinct first preprocess");
      return;
    }
    txn.put(key, preprocess);
  }
  pub fn first_preprocess<G: Get>(getter: &G, id: [u8; 32]) -> Option<Vec<u8>> {
    getter.get(Self::first_preprocess_key(id))
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
}
