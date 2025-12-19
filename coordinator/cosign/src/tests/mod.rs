#[cfg(test)]
mod delay;

#[cfg(test)]
mod intend;

use blake2::{Digest, Blake2b256};
use core::future::Future;
use std::{
  collections::{HashMap, HashSet},
  sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, OnceLock,
  },
};

use rand_core::{OsRng, RngCore};

use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey};

use serai_client_serai::{
  abi::{
    primitives::{
      crypto::Public,
      merkle::{IncrementalUnbalancedMerkleTree, UnbalancedMerkleTree},
      network_id::ExternalNetworkId,
      BlockHash,
    },
    Block, Event, Header, HeaderV1, BLOCK_HEADER_BRANCH_TAG, BLOCK_HEADER_LEAF_TAG,
  },
  Events,
};

use crate::{
  SeraiRpc,
  intend::{CosignIntendTask},
  COSIGN_CONTEXT, Cosign, SignedCosign,
};
use serai_db::MemDb;

struct TestLogger;

static LOG_ENABLED: AtomicBool = AtomicBool::new(true);

impl log::Log for TestLogger {
  fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
    LOG_ENABLED.load(Ordering::Relaxed)
  }

  fn log(&self, _record: &log::Record<'_>) {}

  fn flush(&self) {}
}

fn init_logger() {
  static LOGGER: TestLogger = TestLogger;
  static INIT: OnceLock<()> = OnceLock::new();
  INIT.get_or_init(|| {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Trace);
  });
}

pub(crate) fn cosign_fixture(seed: [u8; 32], cosigner: ExternalNetworkId) -> Cosign {
  let block_number = u64::from_le_bytes(seed[..8].try_into().unwrap());
  let block_hash = seed.map(|b| b ^ 0xAA);

  Cosign { global_session: seed, block_number, block_hash: BlockHash(block_hash), cosigner }
}

pub(crate) fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
  MiniSecretKey::from_bytes(&seed)
    .expect("test seeds should always create a keypair")
    .expand_to_keypair(ExpansionMode::Uniform)
}

pub(crate) fn sr25519_fixture() -> schnorrkel::Keypair {
  let mut seed = [0u8; 32];

  loop {
    OsRng.fill_bytes(&mut seed);
    if let Ok(mini) = schnorrkel::MiniSecretKey::from_bytes(&seed) {
      let keypair = mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
      break keypair;
    }
  }
}

pub(crate) fn sign_cosign(cosign: Cosign, keypair: &schnorrkel::Keypair) -> SignedCosign {
  let sig = keypair.sign_simple(COSIGN_CONTEXT, &cosign.signature_message());
  SignedCosign { cosign, signature: sig.to_bytes() }
}

pub(crate) fn signed_cosign_fixture(
  seed: [u8; 32],
  cosigner: ExternalNetworkId,
) -> (SignedCosign, Public) {
  let cosign = cosign_fixture(seed, cosigner);
  let keypair = keypair_from_seed(seed.map(|b| b ^ 0x55));
  let signature = keypair.sign_simple(COSIGN_CONTEXT, &cosign.signature_message());

  (SignedCosign { cosign, signature: signature.to_bytes() }, Public(keypair.public.to_bytes()))
}

#[derive(Clone)]
pub(crate) struct Serai {
  pub(crate) block_by_number_error: Option<String>,
  pub(crate) events_error: Option<String>,
  pub(crate) blocks_by_number: HashMap<u64, Block>,
  pub(crate) events_by_hash: HashMap<BlockHash, Events>,
  pub(crate) builds_upon: IncrementalUnbalancedMerkleTree,
  pub(crate) missing_blocks: HashSet<u64>,
}

impl Default for Serai {
  fn default() -> Self {
    Self {
      block_by_number_error: None,
      events_error: None,
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

    if number > 0u64 {
      self.blocks_by_number.insert(number, block);
    }

    block_hash
  }

  pub(crate) fn new_events(&mut self, block_hash: BlockHash) {
    self.events_by_hash = HashMap::from([(block_hash, Events::new())]);
  }

  pub(crate) fn set_events(&mut self, block_hash: BlockHash, events: Vec<Event>) {
    self.events_by_hash.insert(block_hash, Events::with(events));
  }

  pub(crate) fn builds_upon(&self) -> &IncrementalUnbalancedMerkleTree {
    &self.builds_upon
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
    let err = self.block_by_number_error.clone();
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
    let err = self.events_error.clone();
    let events = self.events_by_hash.get(&block).cloned().unwrap_or_default();
    async move {
      if let Some(e) = err {
        return Err(e);
      }
      Ok(events)
    }
  }
}

pub(crate) struct TestEnvironment {
  pub(crate) serai: Serai,
  pub(crate) db: MemDb,
}

impl Default for TestEnvironment {
  fn default() -> Self {
    Self { serai: Serai::new(), db: MemDb::new() }
  }
}

impl TestEnvironment {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  pub(crate) fn from_serai(serai: Serai) -> Self {
    Self { serai, db: MemDb::new() }
  }

  pub(crate) fn into_task(&self) -> CosignIntendTask<MemDb, Serai> {
    CosignIntendTask { db: self.db.clone(), serai: self.serai.clone() }
  }
}
