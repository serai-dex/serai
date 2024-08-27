use serai_db::{Get, DbTxn, create_db};

create_db!(
  ScannerIndex {
    // A lookup of a block's number to its ID
    BlockId: (number: u64) -> [u8; 32],
    // A lookup of a block's ID to its number
    BlockNumber: (id: [u8; 32]) -> u64,

    // The latest finalized block to appear on the blockchain
    LatestFinalizedBlock: () -> u64,
  }
);

pub(crate) struct IndexDb;
impl IndexDb {
  pub(crate) fn set_block(txn: &mut impl DbTxn, number: u64, id: [u8; 32]) {
    BlockId::set(txn, number, &id);
    BlockNumber::set(txn, id, &number);
  }
  pub(crate) fn block_id(getter: &impl Get, number: u64) -> Option<[u8; 32]> {
    BlockId::get(getter, number)
  }
  pub(crate) fn block_number(getter: &impl Get, id: [u8; 32]) -> Option<u64> {
    BlockNumber::get(getter, id)
  }

  pub(crate) fn set_latest_finalized_block(txn: &mut impl DbTxn, latest_finalized_block: u64) {
    LatestFinalizedBlock::set(txn, &latest_finalized_block);
  }
  pub(crate) fn latest_finalized_block(getter: &impl Get) -> Option<u64> {
    LatestFinalizedBlock::get(getter)
  }
}
