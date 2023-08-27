use scale::Encode;
use serai_client::primitives::{NetworkId, BlockHash};

pub use serai_db::*;

use crate::tributary::TributarySpec;

#[derive(Debug)]
pub struct MainDb<'a, D: Db>(&'a mut D);
impl<'a, D: Db> MainDb<'a, D> {
  pub fn new(db: &'a mut D) -> Self {
    Self(db)
  }

  fn main_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"MAIN", dst, key)
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

  fn batches_in_block_key(network: NetworkId, block: [u8; 32]) -> Vec<u8> {
    Self::main_key(b"batches_in_block", (network, block).encode())
  }
  pub fn batches_in_block<G: Get>(
    getter: &G,
    network: NetworkId,
    block: [u8; 32],
  ) -> Vec<[u8; 32]> {
    getter
      .get(Self::batches_in_block_key(network, block))
      .expect("asking for batches in block for block without batches")
      .chunks(32)
      .map(|id| id.try_into().unwrap())
      .collect()
  }
  pub fn add_batch_to_block(
    txn: &mut D::Transaction<'_>,
    network: NetworkId,
    block: BlockHash,
    id: [u8; 32],
  ) {
    let key = Self::batches_in_block_key(network, block.0);
    let Some(mut existing) = txn.get(&key) else {
      txn.put(&key, id);
      return;
    };

    if existing.chunks(32).any(|existing_id| existing_id == id) {
      // TODO: Is this an invariant?
      return;
    }

    existing.extend(id);
    txn.put(&key, existing);
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
}
