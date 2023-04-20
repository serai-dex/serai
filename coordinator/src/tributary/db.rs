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
    self.0.get(Self::block_key(genesis)).unwrap_or(genesis.to_vec()).try_into().unwrap()
  }

  fn dkg_attempt_key(genesis: [u8; 32]) -> Vec<u8> {
    Self::tributary_key(b"dkg_attempt", genesis)
  }
  pub fn dkg_attempt<G: Get>(getter: &G, genesis: [u8; 32]) -> u32 {
    u32::from_le_bytes(
      getter.get(Self::dkg_attempt_key(genesis)).unwrap_or(vec![0; 4]).try_into().unwrap(),
    )
  }

  fn dkg_data_received_key(label: &'static [u8], genesis: &[u8], attempt: u32) -> Vec<u8> {
    Self::tributary_key(
      b"dkg_data_received",
      [label, genesis, attempt.to_le_bytes().as_ref()].concat(),
    )
  }
  fn dkg_data_key(
    label: &'static [u8],
    genesis: &[u8],
    signer: &<Ristretto as Ciphersuite>::G,
    attempt: u32,
  ) -> Vec<u8> {
    Self::tributary_key(
      b"dkg_data",
      [label, genesis, signer.to_bytes().as_ref(), attempt.to_le_bytes().as_ref()].concat(),
    )
  }
  pub fn dkg_data<G: Get>(
    label: &'static [u8],
    getter: &G,
    genesis: [u8; 32],
    signer: &<Ristretto as Ciphersuite>::G,
    attempt: u32,
  ) -> Option<Vec<u8>> {
    getter.get(Self::dkg_data_key(label, &genesis, signer, attempt))
  }
  pub fn set_dkg_data(
    label: &'static [u8],
    txn: &mut D::Transaction<'_>,
    genesis: [u8; 32],
    signer: &<Ristretto as Ciphersuite>::G,
    attempt: u32,
    data: &[u8],
  ) -> u16 {
    let received_key = Self::dkg_data_received_key(label, &genesis, attempt);
    let mut received =
      u16::from_le_bytes(txn.get(&received_key).unwrap_or(vec![0; 2]).try_into().unwrap());
    received += 1;

    txn.put(received_key, received.to_le_bytes());
    txn.put(Self::dkg_data_key(label, &genesis, signer, attempt), data);

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
