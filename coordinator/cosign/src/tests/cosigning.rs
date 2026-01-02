use std::{collections::HashMap, time::Instant};

use borsh::{BorshDeserialize, BorshSerialize};

use blake2::{Blake2s256, Digest};

use serai_cosign_types::COSIGN_CONTEXT;
use serai_db::{Db as _, DbTxn, MemDb};

use serai_client_serai::abi::primitives::{
  BlockHash,
  crypto::Public,
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
};

use crate::{
  BROADCAST_FREQUENCY, Cosign, CosignIntent, Cosigning, Faulted, FaultedSession, Faults,
  GlobalSession, GlobalSessions, GlobalSessionsLastBlock, IntakeCosignError,
  NetworksLatestCosignedBlock, SeraiRpc, SignedCosign, SubstrateBlockHash,
  delay::LatestCosignedBlockNumber,
  evaluator::CurrentlyEvaluatedGlobalSession,
  tests::{TestRequest, intend::Serai, sign_cosign, sr25519_fixture},
};

use crate::intend::IntendedCosigns;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct TestGlobalSession {
  start_block_number: u64,
  sets: Vec<ExternalValidatorSet>,
  keys: HashMap<ExternalNetworkId, Public>,
  stakes: HashMap<ExternalNetworkId, u64>,
  total_stake: u64,
}
impl TestGlobalSession {
  fn id(&self) -> [u8; 32] {
    let mut sets = self.sets.clone();
    sets.sort_by_key(|a| borsh::to_vec(a).unwrap());
    Blake2s256::digest(borsh::to_vec(&sets).unwrap()).into()
  }

  fn to_global(&self) -> GlobalSession {
    GlobalSession {
      start_block_number: self.start_block_number,
      sets: self.sets.clone(),
      keys: self.keys.clone(),
      stakes: self.stakes.clone(),
      total_stake: self.total_stake,
    }
  }
}

fn session_fixture() -> TestGlobalSession {
  let network = ExternalNetworkId::Bitcoin;
  let set = ExternalValidatorSet { network, session: Session(0) };

  let mut keys = HashMap::new();
  let mut stakes = HashMap::new();

  let keypair = sr25519_fixture();
  let pubkey = Public(keypair.public.to_bytes());
  keys.insert(network, pubkey);
  stakes.insert(network, 100);

  TestGlobalSession { start_block_number: 1, sets: vec![set], keys, stakes, total_stake: 100 }
}

fn seed_minimal_state(db: &mut MemDb, session: &TestGlobalSession) {
  let mut txn = db.txn();
  let id = session.id();

  // Required by `Cosigning::intake_cosign`.
  GlobalSessions::set(&mut txn, id, &session.to_global());

  // Required by `Cosigning::cosigns_to_rebroadcast` in the non-faulted case.
  CurrentlyEvaluatedGlobalSession::set(&mut txn, &(id, session.to_global()));

  // Required for `intake_cosign` to not classify a session as "future".
  LatestCosignedBlockNumber::set(&mut txn, &0u64);

  txn.commit();
}

#[test]
fn global_session_id_generation() {
  let network1 = ExternalNetworkId::Bitcoin;
  let set1 = ExternalValidatorSet { network: network1, session: Session(0) };
  let set2 = ExternalValidatorSet { network: ExternalNetworkId::Ethereum, session: Session(0) };

  // Create two vectors with the same sets but in different order
  let cosigners1 = vec![set1, set2];
  let cosigners2 = vec![set2, set1];

  // Both should produce the same ID (order-independent)
  let id1 = GlobalSession::id(cosigners1.clone());
  let id2 = GlobalSession::id(cosigners2);
  assert_eq!(id1, id2, "IDs should be the same regardless of input order");

  // Same input should always produce the same ID (deterministic)
  let id3 = GlobalSession::id(cosigners1.clone());
  assert_eq!(id1, id3, "same input should produce the same ID");

  // Different sets should produce different IDs
  let set3 = ExternalValidatorSet { network: network1, session: Session(1) }; // same network as set1, different session
  assert_ne!(
    GlobalSession::id(vec![set1]),
    GlobalSession::id(vec![set3]),
    "different validator sets should produce different IDs"
  );
}

#[test]
fn cosigns_to_rebroadcast_empty_without_state() {
  let db = MemDb::new();
  let cosigning = Cosigning::new(db);
  assert!(cosigning.cosigns_to_rebroadcast().is_empty());
}
