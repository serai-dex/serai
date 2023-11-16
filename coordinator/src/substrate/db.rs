use scale::{Encode, Decode};

pub use serai_db::*;

use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, KeyPair},
};

#[derive(Debug)]
pub struct SubstrateDb<D: Db>(pub D);

create_db!(
  CoordinatorSubstrateDb {
    BlockDb: () -> u64,
    EventDb: (id: &[u8], index: u32) -> [u8; 0],
    SessionDb: (key: &[u8]) -> Session,
    BatchDb: (network: NetworkId, id: u32) -> [u8; 32]
  }
);

impl EventDb {
  pub fn is_unhandled(getter: &impl Get, id: &[u8], index: u32) -> bool {
    Self::get(getter, id, index).is_none()
  }

  pub fn handle_event(txn: &mut impl DbTxn, id: &[u8], index: u32) {
    assert!(Self::is_unhandled(txn, id, index));
    Self::set(txn, id, index, &[0u8; 0]);
  }
}

impl SessionDb {
  pub fn save_session_for_keys(txn: &mut impl DbTxn, key_pair: &KeyPair, session: Session) {
    let existing = Self::get(txn, &key_pair.0);
    // This may trigger if 100% of a DKG are malicious, and they create a key equivalent to a prior
    // key. Since it requires 100% maliciousness, not just 67% maliciousness, this will only assert
    // in a modified-to-be-malicious stack, making it safe
    assert!(existing.is_none() || (existing.as_ref() == Some(&session)));
    Self::set(txn, &key_pair.0, &session);
    Self::set(txn, &key_pair.1, &session);
  }
}
