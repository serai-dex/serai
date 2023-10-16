use std::io::Read;
use scale::Decode;
use serai_client::validator_sets::primitives::{ValidatorSet, KeyPair};

pub use serai_db::*;

use crate::networks::{Block, Network};

create_db!(
  MainDb {
    HandledMessageDb: Vec<u8>,
    PendingActivationsDb: Vec<u8>
  }
);

impl PendingActivationsDb {
  pub fn pending_activation<N: Network, G: Get>(
    getter: &G,
  ) -> Option<(<N::Block as Block<N>>::Id, ValidatorSet, KeyPair)> {
    if let Some(bytes) = getter.get(PendingActivationsDb::key([])) {
      if !bytes.is_empty() {
        let mut slice = bytes.as_slice();
        let (set, key_pair) = <(ValidatorSet, KeyPair)>::decode(&mut slice).unwrap();
        let mut block_before_queue_block = <N::Block as Block<N>>::Id::default();
        slice.read_exact(block_before_queue_block.as_mut()).unwrap();
        assert!(slice.is_empty());
        return Some((block_before_queue_block, set, key_pair));
      }
    }
    None
  }
  pub fn clear_pending_activation(txn: &mut impl DbTxn) {
    txn.put(Self::key([]), []);
  }
}
