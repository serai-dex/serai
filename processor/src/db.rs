use std::io::Read;

use scale::{Encode, Decode};
use serai_client::validator_sets::primitives::{ValidatorSet, KeyPair};

pub use serai_db::*;

use crate::networks::{Block, Network};

create_db!(
  MainDb {
    HandledMessageDb: (id: u64) -> Vec<u8>,
    PendingActivationsDb: () -> Vec<u8>
  }
);

impl PendingActivationsDb {
  pub fn pending_activation<N: Network>(
    getter: &impl Get,
  ) -> Option<(<N::Block as Block<N>>::Id, ValidatorSet, KeyPair)> {
    if let Some(bytes) = Self::get(getter) {
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
}