use std::sync::{OnceLock, MutexGuard, Mutex};

use scale::{Encode, Decode};

pub use serai_db::*;

use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet, KeyPair},
};

create_db! {
  NewSubstrateDb {
    CosignTriggered: () -> (),
    IntendedCosign: () -> (u64, Option<u64>),
    BlockHasEvents: (block: u64) -> u8,
    CosignTransactions: (network: NetworkId) -> Vec<(Session, u64, [u8; 32])>
  }
}

impl IntendedCosign {
  pub fn set_intended_cosign(txn: &mut impl DbTxn, intended: u64) {
    Self::set(txn, &(intended, None::<u64>));
  }
  pub fn set_skipped_cosign(txn: &mut impl DbTxn, skipped: u64) {
    let (intended, prior_skipped) = Self::get(txn).unwrap();
    assert!(prior_skipped.is_none());
    Self::set(txn, &(intended, Some(skipped)));
  }
}

// This guarantees:
// 1) Appended transactions are appended
// 2) Taking cosigns does not clear any TXs which weren't taken
// 3) Taking does actually clear the set
static COSIGN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
pub struct CosignTxn<T: DbTxn>(T, MutexGuard<'static, ()>);
impl<T: DbTxn> CosignTxn<T> {
  pub fn new(txn: T) -> Self {
    Self(txn, COSIGN_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap())
  }
  pub fn commit(self) {
    self.0.commit();
  }
}
impl CosignTransactions {
  // Append a cosign transaction.
  pub fn append_cosign<T: DbTxn>(
    txn: &mut CosignTxn<T>,
    set: ValidatorSet,
    number: u64,
    hash: [u8; 32],
  ) {
    #[allow(clippy::unwrap_or_default)]
    let mut txs = CosignTransactions::get(&txn.0, set.network).unwrap_or(vec![]);
    txs.push((set.session, number, hash));
    CosignTransactions::set(&mut txn.0, set.network, &txs);
  }
  // Peek at the next cosign transaction.
  pub fn peek_cosign(getter: &impl Get, network: NetworkId) -> Option<(Session, u64, [u8; 32])> {
    let mut to_cosign = CosignTransactions::get(getter, network)?;
    if to_cosign.is_empty() {
      None?
    }
    Some(to_cosign.swap_remove(0))
  }
  // Take the next transaction, panicking if it doesn't exist.
  pub fn take_cosign(mut txn: impl DbTxn, network: NetworkId) {
    let _lock = COSIGN_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let mut txs = CosignTransactions::get(&txn, network).unwrap();
    txs.remove(0);
    CosignTransactions::set(&mut txn, network, &txs);
    txn.commit();
  }
}

#[derive(Debug)]
pub struct SubstrateDb<D: Db>(pub D);
impl<D: Db> SubstrateDb<D> {
  pub fn new(db: D) -> Self {
    Self(db)
  }

  fn substrate_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"coordinator_substrate", dst, key)
  }

  fn next_block_key() -> Vec<u8> {
    Self::substrate_key(b"next_block", [])
  }
  pub fn set_next_block(&mut self, block: u64) {
    let mut txn = self.0.txn();
    txn.put(Self::next_block_key(), block.to_le_bytes());
    txn.commit();
  }
  pub fn next_block(&self) -> u64 {
    u64::from_le_bytes(self.0.get(Self::next_block_key()).unwrap_or(vec![0; 8]).try_into().unwrap())
  }

  fn latest_cosigned_block_key() -> Vec<u8> {
    Self::substrate_key(b"latest_cosigned_block", [])
  }
  pub fn set_latest_cosigned_block(txn: &mut D::Transaction<'_>, latest_cosigned_block: u64) {
    txn.put(Self::latest_cosigned_block_key(), latest_cosigned_block.to_le_bytes());
  }
  pub fn latest_cosigned_block<G: Get>(getter: &G) -> u64 {
    let db = u64::from_le_bytes(
      getter.get(Self::latest_cosigned_block_key()).unwrap_or(vec![0; 8]).try_into().unwrap(),
    );
    // Mark the genesis as cosigned
    db.max(1)
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

  fn session_key(key: &[u8]) -> Vec<u8> {
    Self::substrate_key(b"session", key)
  }
  pub fn session_for_key<G: Get>(getter: &G, key: &[u8]) -> Option<Session> {
    getter.get(Self::session_key(key)).map(|bytes| Session::decode(&mut bytes.as_ref()).unwrap())
  }
  pub fn save_session_for_keys(txn: &mut D::Transaction<'_>, key_pair: &KeyPair, session: Session) {
    let session = session.encode();
    let key_0 = Self::session_key(&key_pair.0);
    let existing = txn.get(&key_0);
    // This may trigger if 100% of a DKG are malicious, and they create a key equivalent to a prior
    // key. Since it requires 100% maliciousness, not just 67% maliciousness, this will only assert
    // in a modified-to-be-malicious stack, making it safe
    assert!(existing.is_none() || (existing.as_ref() == Some(&session)));
    txn.put(key_0, session.clone());
    txn.put(Self::session_key(&key_pair.1), session);
  }

  fn batch_instructions_key(network: NetworkId, id: u32) -> Vec<u8> {
    Self::substrate_key(b"batch", (network, id).encode())
  }
  pub fn batch_instructions_hash<G: Get>(
    getter: &G,
    network: NetworkId,
    id: u32,
  ) -> Option<[u8; 32]> {
    getter.get(Self::batch_instructions_key(network, id)).map(|bytes| bytes.try_into().unwrap())
  }
  pub fn save_batch_instructions_hash(
    txn: &mut D::Transaction<'_>,
    network: NetworkId,
    id: u32,
    hash: [u8; 32],
  ) {
    txn.put(Self::batch_instructions_key(network, id), hash);
  }
}
