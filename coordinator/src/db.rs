pub use serai_db::*;

#[derive(Debug)]
pub struct MainDb<D: Db>(pub D);
impl<D: Db> MainDb<D> {
  pub fn new(db: D) -> Self {
    Self(db)
  }

  fn main_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"MAIN", dst, key)
  }

  fn substrate_block_key() -> Vec<u8> {
    Self::main_key(b"substrate_block", [])
  }
  pub fn set_last_substrate_block(&mut self, block: u64) {
    let mut txn = self.0.txn();
    txn.put(Self::substrate_block_key(), block.to_le_bytes());
    txn.commit();
  }
  pub fn last_substrate_block(&self) -> u64 {
    u64::from_le_bytes(
      self.0.get(Self::substrate_block_key()).unwrap_or(vec![0; 8]).try_into().unwrap(),
    )
  }

  fn event_key(id: &[u8], index: u32) -> Vec<u8> {
    Self::main_key(b"event", [id, index.to_le_bytes().as_ref()].concat())
  }
  pub fn handle_event(&mut self, id: [u8; 32], index: u32) {
    let mut txn = self.0.txn();
    txn.put(Self::event_key(&id, index), []);
    txn.commit();
  }
  pub fn handled_event(&self, id: [u8; 32], index: u32) -> bool {
    self.0.get(Self::event_key(&id, index)).is_some()
  }
}
