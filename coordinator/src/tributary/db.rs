use std::io::Read;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

pub use serai_db::*;

#[derive(Debug)]
pub struct TributaryDb<D: Db>(pub D);
impl<D: Db> TributaryDb<D> {
  pub fn new(db: D) -> Self {
    Self(db)
  }

  fn tributary_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"TRIBUTARY", dst, key)
  }

  fn block_key(genesis: [u8; 32]) -> Vec<u8> {
    Self::tributary_key(b"block", genesis)
  }
  pub fn set_last_block(&mut self, genesis: [u8; 32], block: [u8; 32]) {
    let mut txn = self.0.txn();
    txn.put(Self::block_key(genesis), block);
    txn.commit();
  }
  pub fn last_block(&self, genesis: [u8; 32]) -> [u8; 32] {
    self.0.get(Self::block_key(genesis)).map(|last| last.try_into().unwrap()).unwrap_or(genesis)
  }

  // This shouldn't need genesis? Yet it's saner to have then quibble about.
  fn batch_id_key(genesis: &[u8], ext_block: [u8; 32]) -> Vec<u8> {
    Self::tributary_key(b"batch_id", [genesis, ext_block.as_ref()].concat())
  }
  pub fn batch_id<G: Get>(getter: &G, genesis: [u8; 32], ext_block: [u8; 32]) -> Option<[u8; 32]> {
    getter.get(Self::batch_id_key(&genesis, ext_block)).map(|bytes| bytes.try_into().unwrap())
  }

  fn plan_ids_key(genesis: &[u8], block: u64) -> Vec<u8> {
    Self::tributary_key(b"plan_ids", [genesis, block.to_le_bytes().as_ref()].concat())
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

  fn recognized_id_key(label: &'static str, genesis: [u8; 32], id: [u8; 32]) -> Vec<u8> {
    Self::tributary_key(b"recognized", [label.as_bytes(), genesis.as_ref(), id.as_ref()].concat())
  }
  pub fn recognized_id<G: Get>(
    getter: &G,
    label: &'static str,
    genesis: [u8; 32],
    id: [u8; 32],
  ) -> bool {
    getter.get(Self::recognized_id_key(label, genesis, id)).is_some()
  }
  pub fn recognize_id(
    txn: &mut D::Transaction<'_>,
    label: &'static str,
    genesis: [u8; 32],
    id: [u8; 32],
  ) {
    txn.put(Self::recognized_id_key(label, genesis, id), [])
  }

  fn attempt_key(genesis: [u8; 32], id: [u8; 32]) -> Vec<u8> {
    let genesis_ref: &[u8] = genesis.as_ref();
    Self::tributary_key(b"attempt", [genesis_ref, id.as_ref()].concat())
  }
  pub fn attempt<G: Get>(getter: &G, genesis: [u8; 32], id: [u8; 32]) -> u32 {
    u32::from_le_bytes(
      getter.get(Self::attempt_key(genesis, id)).unwrap_or(vec![0; 4]).try_into().unwrap(),
    )
  }

  fn data_received_key(
    label: &'static [u8],
    genesis: [u8; 32],
    id: [u8; 32],
    attempt: u32,
  ) -> Vec<u8> {
    Self::tributary_key(
      b"data_received",
      [label, genesis.as_ref(), id.as_ref(), attempt.to_le_bytes().as_ref()].concat(),
    )
  }
  fn data_key(
    label: &'static [u8],
    genesis: [u8; 32],
    id: [u8; 32],
    attempt: u32,
    signer: <Ristretto as Ciphersuite>::G,
  ) -> Vec<u8> {
    Self::tributary_key(
      b"data",
      [
        label,
        genesis.as_ref(),
        id.as_ref(),
        attempt.to_le_bytes().as_ref(),
        signer.to_bytes().as_ref(),
      ]
      .concat(),
    )
  }
  pub fn data<G: Get>(
    label: &'static [u8],
    getter: &G,
    genesis: [u8; 32],
    id: [u8; 32],
    attempt: u32,
    signer: <Ristretto as Ciphersuite>::G,
  ) -> Option<Vec<u8>> {
    getter.get(Self::data_key(label, genesis, id, attempt, signer))
  }
  pub fn set_data(
    label: &'static [u8],
    txn: &mut D::Transaction<'_>,
    genesis: [u8; 32],
    id: [u8; 32],
    attempt: u32,
    signer: <Ristretto as Ciphersuite>::G,
    data: &[u8],
  ) -> u16 {
    let received_key = Self::data_received_key(label, genesis, id, attempt);
    let mut received =
      u16::from_le_bytes(txn.get(&received_key).unwrap_or(vec![0; 2]).try_into().unwrap());
    received += 1;

    txn.put(received_key, received.to_le_bytes());
    txn.put(Self::data_key(label, genesis, id, attempt, signer), data);

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
