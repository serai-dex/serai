pub use serai_db::*;

#[derive(Debug)]
pub struct SubstrateDb<D: Db>(pub D);
impl<D: Db> SubstrateDb<D> {
  pub fn new(db: D) -> Self {
    Self(db)
  }

  fn substrate_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"coordinator_substrate", dst, key)
  }

  fn block_key() -> Vec<u8> {
    Self::substrate_key(b"block", [])
  }
  pub fn set_next_block(&mut self, block: u64) {
    let mut txn = self.0.txn();
    txn.put(Self::block_key(), block.to_le_bytes());
    txn.commit();
  }
  pub fn next_block(&self) -> u64 {
    u64::from_le_bytes(self.0.get(Self::block_key()).unwrap_or(vec![0; 8]).try_into().unwrap())
  }

  fn event_key(id: &[u8], index: u32) -> Vec<u8> {
    Self::substrate_key(b"event", [id, index.to_le_bytes().as_ref()].concat())
  }
  pub fn handled_event<G: Get>(getter: &G, id: [u8; 32], index: u32) -> bool {
    getter.get(Self::event_key(&id, index)).is_some()
  }
  pub fn handle_event(txn: &mut D::Transaction<'_>, id: [u8; 32], index: u32) {
    assert!(!Self::handled_event(txn, id, index));
    txn.put(Self::event_key(&id, index), []);
  }
}
