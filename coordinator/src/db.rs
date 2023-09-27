use scale::{Encode, Decode};
use serai_client::{primitives::NetworkId, in_instructions::primitives::SignedBatch};

pub use serai_db::*;

use crate::tributary::TributarySpec;

#[derive(Debug)]
pub struct MainDb<'a, D: Db>(&'a mut D);
impl<'a, D: Db> MainDb<'a, D> {
  pub fn new(db: &'a mut D) -> Self {
    Self(db)
  }

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
  pub fn active_tributaries(&self) -> (Vec<u8>, Vec<TributarySpec>) {
    let bytes = self.0.get(Self::acive_tributaries_key()).unwrap_or(vec![]);
    let mut bytes_ref: &[u8] = bytes.as_ref();

    let mut tributaries = vec![];
    while !bytes_ref.is_empty() {
      tributaries.push(TributarySpec::read(&mut bytes_ref).unwrap());
    }

    (bytes, tributaries)
  }
  pub fn add_active_tributary(&mut self, spec: &TributarySpec) {
    let key = Self::acive_tributaries_key();
    let (mut existing_bytes, existing) = self.active_tributaries();
    for tributary in &existing {
      if tributary == spec {
        return;
      }
    }

    spec.write(&mut existing_bytes).unwrap();
    let mut txn = self.0.txn();
    txn.put(key, existing_bytes);
    txn.commit();
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
  pub fn save_batch(&mut self, batch: SignedBatch) {
    let mut txn = self.0.txn();
    txn.put(Self::batch_key(batch.batch.network, batch.batch.id), batch.encode());
    txn.commit();
  }
  pub fn batch(&self, network: NetworkId, id: u32) -> Option<SignedBatch> {
    self
      .0
      .get(Self::batch_key(network, id))
      .map(|batch| SignedBatch::decode(&mut batch.as_ref()).unwrap())
  }
}
