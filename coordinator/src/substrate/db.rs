use scale::Encode;

use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet},
};

pub use serai_db::*;

create_db!(
  SubstrateDb {
    CosignTriggered: () -> (),
    IntendedCosign: () -> (u64, Option<u64>),
    BlockHasEvents: (block: u64) -> u8,
    LatestCosignedBlock: () -> u64,
    NextBlock: () -> u64,
    EventDb: (id: &[u8], index: u32) -> (),
    BatchInstructionsHashDb: (network: NetworkId, id: u32) -> [u8; 32]
  }
);

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

impl LatestCosignedBlock {
  pub fn latest_cosigned_block(getter: &impl Get) -> u64 {
    Self::get(getter).unwrap_or_default().max(1)
  }
}

impl EventDb {
  pub fn is_unhandled(getter: &impl Get, id: &[u8], index: u32) -> bool {
    Self::get(getter, id, index).is_none()
  }

  pub fn handle_event(txn: &mut impl DbTxn, id: &[u8], index: u32) {
    assert!(Self::is_unhandled(txn, id, index));
    Self::set(txn, id, index, &());
  }
}

db_channel! {
  SubstrateDbChannels {
    CosignTransactions: (network: NetworkId) -> (Session, u64, [u8; 32]),
  }
}

impl CosignTransactions {
  // Append a cosign transaction.
  pub fn append_cosign(txn: &mut impl DbTxn, set: ValidatorSet, number: u64, hash: [u8; 32]) {
    CosignTransactions::send(txn, set.network, &(set.session, number, hash))
  }
}
