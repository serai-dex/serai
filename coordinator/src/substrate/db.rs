use scale::Encode;

use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet},
};

pub use serai_db::*;

create_db! {
  SubstrateDb {
    CosignTriggered: () -> (),
    IntendedCosign: () -> (u64, Option<u64>),
    BlockHasEvents: (block: u64) -> u8,
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

db_channel! {
  SubstrateDb {
    CosignTransactions: (network: NetworkId) -> (Session, u64, [u8; 32]),
  }
}
impl CosignTransactions {
  // Append a cosign transaction.
  pub fn append_cosign(txn: &mut impl DbTxn, set: ValidatorSet, number: u64, hash: [u8; 32]) {
    CosignTransactions::send(txn, set.network, &(set.session, number, hash))
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
