use core::marker::PhantomData;
use std::io::Read;

use scale::{Encode, Decode};
use serai_client::validator_sets::primitives::{ValidatorSet, KeyPair};

pub use serai_db::*;

use crate::{
  Plan,
  networks::{Block, Network},
};

#[derive(Debug)]
pub struct MainDb<N: Network, D: Db>(D, PhantomData<N>);
impl<N: Network, D: Db> MainDb<N, D> {
  pub fn new(db: D) -> Self {
    Self(db, PhantomData)
  }

  fn main_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"MAIN", dst, key)
  }

  fn handled_key(id: u64) -> Vec<u8> {
    Self::main_key(b"handled", id.to_le_bytes())
  }
  pub fn handled_message(&self, id: u64) -> bool {
    self.0.get(Self::handled_key(id)).is_some()
  }
  pub fn handle_message(txn: &mut D::Transaction<'_>, id: u64) {
    txn.put(Self::handled_key(id), [])
  }

  fn plan_key(id: &[u8]) -> Vec<u8> {
    Self::main_key(b"plan", id)
  }
  fn signing_key(key: &[u8]) -> Vec<u8> {
    Self::main_key(b"signing", key)
  }
  pub fn save_signing(txn: &mut D::Transaction<'_>, key: &[u8], block_number: u64, plan: &Plan<N>) {
    let id = plan.id();

    {
      let mut signing = txn.get(Self::signing_key(key)).unwrap_or(vec![]);

      // If we've already noted we're signing this, return
      assert_eq!(signing.len() % 32, 0);
      for i in 0 .. (signing.len() / 32) {
        if signing[(i * 32) .. ((i + 1) * 32)] == id {
          return;
        }
      }

      signing.extend(&id);
      txn.put(Self::signing_key(key), id);
    }

    {
      let mut buf = block_number.to_le_bytes().to_vec();
      plan.write(&mut buf).unwrap();
      txn.put(Self::plan_key(&id), &buf);
    }
  }

  pub fn signing(&self, key: &[u8]) -> Vec<(u64, Plan<N>)> {
    let signing = self.0.get(Self::signing_key(key)).unwrap_or(vec![]);
    let mut res = vec![];

    assert_eq!(signing.len() % 32, 0);
    for i in 0 .. (signing.len() / 32) {
      let id = &signing[(i * 32) .. ((i + 1) * 32)];
      let buf = self.0.get(Self::plan_key(id)).unwrap();

      let block_number = u64::from_le_bytes(buf[.. 8].try_into().unwrap());
      let plan = Plan::<N>::read::<&[u8]>(&mut &buf[16 ..]).unwrap();
      assert_eq!(id, &plan.id());
      res.push((block_number, plan));
    }

    res
  }

  pub fn finish_signing(&mut self, txn: &mut D::Transaction<'_>, key: &[u8], id: [u8; 32]) {
    let mut signing = self.0.get(Self::signing_key(key)).unwrap_or(vec![]);
    assert_eq!(signing.len() % 32, 0);

    let mut found = false;
    for i in 0 .. (signing.len() / 32) {
      let start = i * 32;
      let end = i + 32;
      if signing[start .. end] == id {
        found = true;
        signing = [&signing[.. start], &signing[end ..]].concat().to_vec();
        break;
      }
    }

    if !found {
      log::warn!("told to finish signing {} yet wasn't actively signing it", hex::encode(id));
    }

    txn.put(Self::signing_key(key), signing);
  }

  fn pending_activation_key() -> Vec<u8> {
    Self::main_key(b"pending_activation", [])
  }
  pub fn set_pending_activation(
    txn: &mut D::Transaction<'_>,
    block_before_queue_block: <N::Block as Block<N>>::Id,
    set: ValidatorSet,
    key_pair: KeyPair,
  ) {
    let mut buf = (set, key_pair).encode();
    buf.extend(block_before_queue_block.as_ref());
    txn.put(Self::pending_activation_key(), buf);
  }
  pub fn pending_activation<G: Get>(
    getter: &G,
  ) -> Option<(<N::Block as Block<N>>::Id, ValidatorSet, KeyPair)> {
    if let Some(bytes) = getter.get(Self::pending_activation_key()) {
      if !bytes.is_empty() {
        let mut slice = bytes.as_slice();
        let (set, key_pair) = <(ValidatorSet, KeyPair)>::decode(&mut slice).unwrap();
        let mut block_before_queue_block = <N::Block as Block<N>>::Id::default();
        slice.read_exact(block_before_queue_block.as_mut()).unwrap();
        assert!(slice.is_empty());
        return Some((block_before_queue_block, set, key_pair));
      }
    }
    None
  }
  pub fn clear_pending_activation(txn: &mut D::Transaction<'_>) {
    txn.put(Self::pending_activation_key(), []);
  }
}
