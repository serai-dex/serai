use scale::Encode;

use serai_client::primitives::NetworkId;

pub use serai_db::*;

create_db!(
  SubstrateDb {
    NextBlock: () -> u64,
    EventDb: (id: &[u8], index: u32) -> (),
    BatchInstructionsHashDb: (network: NetworkId, id: u32) -> [u8; 32]
  }
);

impl EventDb {
  pub fn is_unhandled(getter: &impl Get, id: &[u8], index: u32) -> bool {
    Self::get(getter, id, index).is_none()
  }

  pub fn handle_event(txn: &mut impl DbTxn, id: &[u8], index: u32) {
    assert!(Self::is_unhandled(txn, id, index));
    Self::set(txn, id, index, &());
  }
}
