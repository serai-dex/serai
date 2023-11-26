use serai_db::{DbTxn, Db};

use crate::messages::*;

#[derive(Clone, Debug)]
pub(crate) struct Queue<D: Db>(pub(crate) D, pub(crate) Service, pub(crate) Service);
impl<D: Db> Queue<D> {
  fn key(domain: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    [&[u8::try_from(domain.len()).unwrap()], domain, key.as_ref()].concat()
  }

  fn message_count_key(&self) -> Vec<u8> {
    Self::key(b"message_count", borsh::to_vec(&(self.1, self.2)).unwrap())
  }
  pub(crate) fn message_count(&self) -> u64 {
    self
      .0
      .get(self.message_count_key())
      .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
      .unwrap_or(0)
  }

  fn last_acknowledged_key(&self) -> Vec<u8> {
    Self::key(b"last_acknowledged", borsh::to_vec(&(self.1, self.2)).unwrap())
  }
  pub(crate) fn last_acknowledged(&self) -> Option<u64> {
    self
      .0
      .get(self.last_acknowledged_key())
      .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
  }

  fn message_key(&self, id: u64) -> Vec<u8> {
    Self::key(b"message", borsh::to_vec(&(self.1, self.2, id)).unwrap())
  }
  // TODO: This is fine as-used, yet gets from the DB while having a txn. It should get from the
  // txn
  pub(crate) fn queue_message(
    &mut self,
    txn: &mut D::Transaction<'_>,
    mut msg: QueuedMessage,
  ) -> u64 {
    let id = self.message_count();
    msg.id = id;
    let msg_key = self.message_key(id);
    let msg_count_key = self.message_count_key();

    txn.put(msg_key, borsh::to_vec(&msg).unwrap());
    txn.put(msg_count_key, (id + 1).to_le_bytes());

    id
  }

  pub(crate) fn get_message(&self, id: u64) -> Option<QueuedMessage> {
    let msg: Option<QueuedMessage> =
      self.0.get(self.message_key(id)).map(|bytes| borsh::from_slice(&bytes).unwrap());
    if let Some(msg) = msg.as_ref() {
      assert_eq!(msg.id, id, "message stored at {id} has ID {}", msg.id);
    }
    msg
  }

  pub(crate) fn ack_message(&mut self, id: u64) {
    let ack_key = self.last_acknowledged_key();
    let mut txn = self.0.txn();
    txn.put(ack_key, id.to_le_bytes());
    txn.commit();
  }
}
