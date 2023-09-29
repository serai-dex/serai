use core::marker::PhantomData;
use std::io::Read;

use scale::{Encode, Decode};
use serai_client::validator_sets::primitives::{ValidatorSet, KeyPair};

pub use serai_db::*;

use crate::networks::{Block, Network};

createDb!(
  MainDb {
    HandledMessageDb,
    PendingActivationsDb
  }
);

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
