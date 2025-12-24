#[cfg(test)]
mod intend;

#[cfg(test)]
mod delay;

use blake2::{Digest, Blake2b256};
use serai_task::ContinuallyRan;
use core::future::Future;
use std::{
  collections::{HashMap, HashSet},
};

use serai_client_serai::{
  abi::{
    primitives::{
      merkle::{IncrementalUnbalancedMerkleTree, UnbalancedMerkleTree},
      BlockHash,
    },
    Block, Event, Header, HeaderV1, BLOCK_HEADER_BRANCH_TAG, BLOCK_HEADER_LEAF_TAG,
  },
  Events,
};

use crate::{
  COSIGN_CONTEXT, Cosign, SeraiRpc, SignedCosign, delay::CosignDelayTask, intend::CosignIntendTask,
};
use serai_db::MemDb;

pub(crate) fn sr25519_fixture() -> schnorrkel::Keypair {
  // Use a fixed seed to ensure deterministic keypairs across test calls.
  let seed = [42u8; 32];
  let mini = schnorrkel::MiniSecretKey::from_bytes(&seed).expect("fixed seed should be valid");
  mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519)
}

pub(crate) fn sign_cosign(cosign: Cosign, keypair: &schnorrkel::Keypair) -> SignedCosign {
  let sig = keypair.sign_simple(COSIGN_CONTEXT, &cosign.signature_message());
  SignedCosign { cosign, signature: sig.to_bytes() }
}

#[derive(Clone)]
pub(crate) struct Serai {
  pub(crate) block_by_number_error: HashMap<u64, String>,
  pub(crate) events_error: HashMap<BlockHash, String>,
  pub(crate) blocks_by_number: HashMap<u64, Block>,
  pub(crate) events_by_hash: HashMap<BlockHash, Events>,
  pub(crate) builds_upon: IncrementalUnbalancedMerkleTree,
  pub(crate) missing_blocks: HashSet<u64>,
}

impl Default for Serai {
  fn default() -> Self {
    Self {
      block_by_number_error: HashMap::new(),
      events_error: HashMap::new(),
      blocks_by_number: HashMap::new(),
      events_by_hash: HashMap::new(),
      builds_upon: IncrementalUnbalancedMerkleTree::new(),
      missing_blocks: HashSet::new(),
    }
  }
}

impl Serai {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  pub(crate) fn set_block_not_found(&mut self, block_number: u64) {
    self.missing_blocks.insert(block_number);
  }

  pub(crate) fn set_block_error(&mut self, block_number: u64, error: &str) {
    self.block_by_number_error.insert(block_number, error.to_string());
  }

  pub(crate) fn set_events_error(&mut self, block_hash: BlockHash, error: &str) {
    self.events_error.insert(block_hash, error.to_string());
  }

  pub(crate) fn make_block(&mut self, number: u64) -> BlockHash {
    let block = Block {
      header: Header::V1(HeaderV1 {
        number,
        builds_upon: self.builds_upon.clone().calculate(BLOCK_HEADER_BRANCH_TAG),
        unix_time_in_millis: 0,
        transactions_commitment: UnbalancedMerkleTree::EMPTY,
        events_commitment: UnbalancedMerkleTree::EMPTY,
        consensus_commitment: [0; 32],
      }),
      transactions: vec![],
    };

    let block_hash = block.header.hash();
    self.builds_upon.append(
      BLOCK_HEADER_BRANCH_TAG,
      Blake2b256::new_with_prefix([BLOCK_HEADER_LEAF_TAG])
        .chain_update(block_hash.0)
        .finalize()
        .into(),
    );

    self.blocks_by_number.insert(number, block);

    block_hash
  }

  pub(crate) fn initialize_empty_events(&mut self, block_hash: BlockHash) {
    self.events_by_hash = HashMap::from([(block_hash, Events::new())]);
  }

  pub(crate) fn set_events(&mut self, block_hash: BlockHash, events: Vec<Event>) {
    self.events_by_hash.insert(block_hash, Events::with(events));
  }
}

impl SeraiRpc for Serai {
  fn latest_finalized_block_number(&self) -> impl Send + Future<Output = Result<u64, String>> {
    let latest = self.blocks_by_number.keys().copied().max().unwrap_or(0);
    async move { Ok(latest) }
  }

  fn block_by_number(
    &self,
    block: u64,
  ) -> impl Send + Future<Output = Result<Option<Block>, String>> {
    let err = self.block_by_number_error.get(&block).cloned();
    let block_entry = self.blocks_by_number.get(&block).cloned();
    let is_missing = self.missing_blocks.contains(&block);

    async move {
      if let Some(e) = err {
        return Err(e);
      }
      if is_missing {
        return Ok(None);
      }
      Ok(block_entry)
    }
  }

  fn events(&self, block: BlockHash) -> impl Send + Future<Output = Result<Events, String>> {
    let err = self.events_error.get(&block).cloned();
    let events = self.events_by_hash.get(&block).cloned().unwrap_or_default();
    async move {
      if let Some(e) = err {
        return Err(e);
      }
      Ok(events)
    }
  }
}

pub(crate) struct Test {
  pub(crate) serai: Serai,
  pub(crate) db: MemDb,
}

impl Default for Test {
  fn default() -> Self {
    Self { serai: Serai::new(), db: MemDb::new() }
  }
}

impl Test {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  #[allow(dead_code)]
  pub(crate) fn from_serai(serai: Serai) -> Self {
    Self { serai, db: MemDb::new() }
  }

  fn into_intend_task(&self) -> CosignIntendTask<MemDb, Serai> {
    CosignIntendTask { db: self.db.clone(), serai: self.serai.clone() }
  }

  fn into_delay_task(&self) -> CosignDelayTask<MemDb> {
    CosignDelayTask { db: self.db.clone() }
  }

  pub(crate) async fn assert_task_run_and_check_progress(
    task: &mut impl ContinuallyRan,
    made_progress: bool,
  ) {
    assert_eq!(task.run_iteration().await.unwrap(), made_progress);
  }

  pub(crate) async fn assert_task_failed(task: &mut impl ContinuallyRan, error: &str) {
    let err = task.run_iteration().await.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(err_str.contains(error), "{err_str}");
  }
}
