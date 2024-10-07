use serai_client::primitives::ExternalNetworkId;

pub use serai_db::*;

mod inner_db {
  use super::*;

  create_db!(
    SubstrateDb {
      NextBlock: () -> u64,
      HandledEvent: (block: [u8; 32]) -> u32,
      BatchInstructionsHashDb: (network: ExternalNetworkId, id: u32) -> [u8; 32]
    }
  );
}
pub(crate) use inner_db::{NextBlock, BatchInstructionsHashDb};

pub struct HandledEvent;
impl HandledEvent {
  fn next_to_handle_event(getter: &impl Get, block: [u8; 32]) -> u32 {
    inner_db::HandledEvent::get(getter, block).map_or(0, |last| last + 1)
  }
  pub fn is_unhandled(getter: &impl Get, block: [u8; 32], event_id: u32) -> bool {
    let next = Self::next_to_handle_event(getter, block);
    assert!(next >= event_id);
    next == event_id
  }
  pub fn handle_event(txn: &mut impl DbTxn, block: [u8; 32], index: u32) {
    assert!(Self::next_to_handle_event(txn, block) == index);
    inner_db::HandledEvent::set(txn, block, &index);
  }
}
