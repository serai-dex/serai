use std::io::Read;

use scale::{Encode, Decode};
use serai_client::validator_sets::primitives::{Session, KeyPair};

pub use serai_db::*;

use crate::networks::{Block, Network};

create_db!(
  MainDb {
    HandledMessageDb: (id: u64) -> (),
    PendingActivationsDb: () -> Vec<u8>
  }
);

impl PendingActivationsDb {
  pub fn pending_activation<N: Network>(
    getter: &impl Get,
  ) -> Option<(<N::Block as Block<N>>::Id, Session, KeyPair)> {
    if let Some(bytes) = Self::get(getter) {
      if !bytes.is_empty() {
        let mut slice = bytes.as_slice();
        let (session, key_pair) = <(Session, KeyPair)>::decode(&mut slice).unwrap();
        let mut block_before_queue_block = <N::Block as Block<N>>::Id::default();
        slice.read_exact(block_before_queue_block.as_mut()).unwrap();
        assert!(slice.is_empty());
        return Some((block_before_queue_block, session, key_pair));
      }
    }
    None
  }
  pub fn set_pending_activation<N: Network>(
    txn: &mut impl DbTxn,
    block_before_queue_block: &<N::Block as Block<N>>::Id,
    session: Session,
    key_pair: KeyPair,
  ) {
    let mut buf = (session, key_pair).encode();
    buf.extend(block_before_queue_block.as_ref());
    Self::set(txn, &buf);
  }
}
