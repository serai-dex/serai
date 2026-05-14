use core::str::FromStr as _;

use serai_db::{DbTxn as _, Db};

use serai_env::Environment;

use crate::*;

const MESSAGE_RETENTION: u64 = 10_000;

#[derive(Clone, Debug)]
pub(crate) struct Queue<D: Db> {
  db: D,
  from: Service,
  to: Service,
  message_retention: u64,
}
impl<D: Db> Queue<D> {
  pub(crate) fn new(environment: &Environment, db: D, from: Service, to: Service) -> Self {
    let message_retention = environment
      .var("MESSAGE_RETENTION")
      .map(|retention| (**retention).clone())
      .unwrap_or(format!("{MESSAGE_RETENTION}"));
    let message_retention =
      u64::from_str(&message_retention).expect("`MESSAGE_RETENTION` was not a valid `u64`");

    Self { db, from, to, message_retention }
  }

  fn key(domain: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    [&[u8::try_from(domain.len()).unwrap()], domain, key.as_ref()].concat()
  }

  fn message_count_key(&self) -> Vec<u8> {
    Self::key(b"message_count", borsh::to_vec(&(self.from, self.to)).unwrap())
  }
  pub(crate) fn message_count(&self) -> u64 {
    self
      .db
      .get(self.message_count_key())
      .map_or(0, |bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
  }

  fn last_acknowledged_key(&self) -> Vec<u8> {
    Self::key(b"last_acknowledged", borsh::to_vec(&(self.from, self.to)).unwrap())
  }
  pub(crate) fn last_acknowledged(&self) -> Option<u64> {
    self
      .db
      .get(self.last_acknowledged_key())
      .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
  }

  fn message_key(&self, id: u64) -> Vec<u8> {
    Self::key(b"message", borsh::to_vec(&(self.from, self.to, id)).unwrap())
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
      self.db.get(self.message_key(id)).map(|bytes| borsh::from_slice(&bytes).unwrap());
    if let Some(msg) = msg.as_ref() {
      assert_eq!(msg.id, id, "message stored at {id} has ID {}", msg.id);
    }
    msg
  }

  pub(crate) fn ack_message(&mut self, id: u64) {
    let ack_key = self.last_acknowledged_key();

    let old_key = id.checked_sub(self.message_retention).map(|old| self.message_key(old));

    let mut txn = self.db.txn();
    txn.put(ack_key, id.to_le_bytes());
    if let Some(old_key) = old_key {
      txn.del(old_key);
    }
    txn.commit();
  }
}
