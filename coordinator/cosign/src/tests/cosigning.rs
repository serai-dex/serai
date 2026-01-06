use std::{collections::HashMap, time::Duration};

use borsh::{BorshDeserialize, BorshSerialize};

use blake2::{Blake2s256, Digest};

use serai_db::{Db as _, DbTxn, MemDb};

use serai_client_serai::abi::primitives::{
  BlockHash,
  crypto::Public,
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
};

use crate::{
  Cosign, CosignIntent, Cosigning, Faulted, FaultedSession, Faults, GlobalSession, GlobalSessions,
  GlobalSessionsLastBlock, IntakeCosignError, NetworksLatestCosignedBlock, SignedCosign,
  SubstrateBlockHash,
  delay::LatestCosignedBlockNumber,
  evaluator::CurrentlyEvaluatedGlobalSession,
  intend::IntendedCosigns,
  tests::{TestRequest, intend::Serai},
};

use serai_cosign_types::tests::{
  fixture_public_key, public_key_from_seed, sign_cosign_with_fixture, sign_cosign_with_seed,
};

const FIXTURE_SEED: [u8; 32] = [0xff; 32];

struct Sr25519Fixture {
  seed: [u8; 32],
}

impl Sr25519Fixture {
  fn public_bytes(&self) -> [u8; 32] {
    if self.seed == FIXTURE_SEED {
      fixture_public_key()
    } else {
      public_key_from_seed(self.seed)
    }
  }
}

fn sr25519_fixture() -> Sr25519Fixture {
  Sr25519Fixture { seed: FIXTURE_SEED }
}

fn sign_cosign(cosign: Cosign, fixture: &Sr25519Fixture) -> SignedCosign {
  if fixture.seed == FIXTURE_SEED {
    sign_cosign_with_fixture(cosign)
  } else {
    sign_cosign_with_seed(cosign, fixture.seed)
  }
}

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

  let fixture = sr25519_fixture();
  let pubkey = Public(fixture.public_bytes());
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
fn temporal_returns_true_for_temporal_errors() {
  assert!(IntakeCosignError::NotYetIndexedBlock.temporal());
  assert!(IntakeCosignError::StaleCosign.temporal());
  assert!(IntakeCosignError::UnrecognizedGlobalSession.temporal());
  assert!(IntakeCosignError::FutureGlobalSession.temporal());
}

#[test]
fn temporal_returns_false_for_non_temporal_errors() {
  assert!(!IntakeCosignError::BeforeGlobalSessionStart.temporal());
  assert!(!IntakeCosignError::AfterGlobalSessionEnd.temporal());
  assert!(!IntakeCosignError::NonParticipatingNetwork.temporal());
  assert!(!IntakeCosignError::InvalidSignature.temporal());
}

#[tokio::test]
async fn spawn_creates_cosigning_instance() {
  let db = MemDb::new();
  let serai = Serai::default();
  let (request, _calls) = TestRequest::new(false);
  let cosigning = Cosigning::spawn(db, serai, request, vec![]);

  assert!(cosigning.cosigns_to_rebroadcast().is_empty());
}

#[tokio::test]
async fn spawn_with_tasks_to_run_upon_cosigning() {
  use serai_task::Task;

  let db = MemDb::new();
  let serai = Serai::default();
  let (request, _calls) = TestRequest::new(false);

  let (_task, task_handle) = Task::new();
  let tasks_to_run = vec![task_handle];

  let cosigning = Cosigning::spawn(db.clone(), serai, request, tasks_to_run);

  assert!(cosigning.cosigns_to_rebroadcast().is_empty());
}

#[tokio::test]
async fn spawn_initializes_cosigning_instance_correctly() {
  let db = MemDb::new();
  let serai = Serai::default();
  let (request, _calls) = TestRequest::new(false);

  let cosigning = Cosigning::spawn(db.clone(), serai, request, vec![]);

  assert!(cosigning.cosigns_to_rebroadcast().is_empty());

  let latest = Cosigning::<MemDb>::latest_cosigned_block_number(&db);
  assert!(latest.is_ok());
  assert_eq!(latest.unwrap(), 0);
}

#[tokio::test]
async fn spawn_tasks_chain_correctly() {
  let db = MemDb::new();
  let serai = Serai::default();
  let (request, _calls) = TestRequest::new(false);

  let _cosigning = Cosigning::spawn(db.clone(), serai, request, vec![]);

  tokio::time::sleep(Duration::from_millis(10)).await;

  let latest = Cosigning::<MemDb>::latest_cosigned_block_number(&db);
  assert!(latest.is_ok());
}

#[test]
fn latest_cosigned_block_number_defaults_to_zero() {
  let db = MemDb::new();
  assert_eq!(Cosigning::<MemDb>::latest_cosigned_block_number(&db).unwrap(), 0);
}

#[test]
fn latest_cosigned_block_number_errors_when_faulted() {
  let mut db = MemDb::new();
  {
    let mut txn = db.txn();
    FaultedSession::set(&mut txn, &[1u8; 32]);
    txn.commit();
  }
  assert!(matches!(Cosigning::<MemDb>::latest_cosigned_block_number(&db), Err(Faulted)));
}

#[test]
fn latest_cosigned_block_number_returns_stored_value() {
  let mut db = MemDb::new();
  {
    let mut txn = db.txn();
    LatestCosignedBlockNumber::set(&mut txn, &42u64);
    txn.commit();
  }
  assert_eq!(Cosigning::<MemDb>::latest_cosigned_block_number(&db).unwrap(), 42);
}

#[test]
fn cosigned_block_returns_none_beyond_latest() {
  let mut db = MemDb::new();
  {
    let mut txn = db.txn();
    LatestCosignedBlockNumber::set(&mut txn, &5u64);
    txn.commit();
  }
  assert_eq!(Cosigning::<MemDb>::cosigned_block(&db, 6).unwrap(), None);
}

#[test]
fn cosigned_block_returns_hash_when_in_range() {
  let mut db = MemDb::new();
  let block_hash = BlockHash([9u8; 32]);
  {
    let mut txn = db.txn();
    LatestCosignedBlockNumber::set(&mut txn, &5u64);
    SubstrateBlockHash::set(&mut txn, 3, &block_hash);
    txn.commit();
  }
  assert_eq!(Cosigning::<MemDb>::cosigned_block(&db, 3).unwrap(), Some(block_hash));
}

#[test]
fn cosigned_block_errors_when_faulted() {
  let mut db = MemDb::new();
  {
    let mut txn = db.txn();
    FaultedSession::set(&mut txn, &[1u8; 32]);
    txn.commit();
  }
  assert!(matches!(Cosigning::<MemDb>::cosigned_block(&db, 0), Err(Faulted)));
}

#[tokio::test]
async fn cosigning_cosigned_block_returns_correct_hash() {
  let mut db = MemDb::new();
  let block_hash_5 = BlockHash([42u8; 32]);
  let block_hash_10 = BlockHash([43u8; 32]);

  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, 5, &block_hash_5);
    SubstrateBlockHash::set(&mut txn, 10, &block_hash_10);
    LatestCosignedBlockNumber::set(&mut txn, &10u64);
    txn.commit();
  }

  let result = Cosigning::<MemDb>::cosigned_block(&db, 5);
  assert!(result.is_ok());
  assert_eq!(result.unwrap(), Some(block_hash_5));

  let result_10 = Cosigning::<MemDb>::cosigned_block(&db, 10);
  assert!(result_10.is_ok());
  assert_eq!(result_10.unwrap(), Some(block_hash_10));

  let result_11 = Cosigning::<MemDb>::cosigned_block(&db, 11);
  assert!(result_11.is_ok());
  assert_eq!(result_11.unwrap(), None);
}

#[test]
fn notable_cosigns_empty_without_cosigns() {
  let db = MemDb::new();
  let cosigns = Cosigning::<MemDb>::notable_cosigns(&db, [1u8; 32]);
  assert!(cosigns.is_empty());
}

#[test]
fn notable_cosigns_returns_cosigns_for_session() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let block_hash = BlockHash([9u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
    txn.commit();
  }

  let cosign =
    Cosign { global_session: id, block_number, block_hash, cosigner: ExternalNetworkId::Bitcoin };
  let signed = sign_cosign(cosign, &keypair);

  let mut cosigning = Cosigning::new(db.clone());
  cosigning.intake_cosign(&signed).unwrap();

  let notable = Cosigning::<MemDb>::notable_cosigns(&db, id);
  assert_eq!(notable.len(), 1);
  assert_eq!(notable[0].cosign.block_number, block_number);
  assert_eq!(notable[0].cosign.block_hash, block_hash);
  assert_eq!(notable[0].cosign.cosigner, ExternalNetworkId::Bitcoin);
}

#[test]
fn cosigns_to_rebroadcast_excludes_cosigns_from_different_global_session() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let our_hash = BlockHash([1u8; 32]);
  let faulty_hash = BlockHash([2u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &our_hash);
    txn.commit();
  }

  let faulty_cosign = Cosign {
    global_session: id,
    block_number,
    block_hash: faulty_hash,
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let faulty_signed = sign_cosign(faulty_cosign, &keypair);

  let mut cosigning = Cosigning::new(db.clone());
  cosigning.intake_cosign(&faulty_signed).unwrap();

  let different_session_id = [99u8; 32];
  let different_cosign = Cosign {
    global_session: different_session_id,
    block_number,
    block_hash: our_hash,
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let different_signed = sign_cosign(different_cosign, &keypair);
  {
    let mut txn = db.txn();
    NetworksLatestCosignedBlock::set(&mut txn, id, ExternalNetworkId::Bitcoin, &different_signed);
    txn.commit();
  }

  let cosigning = Cosigning::new(db);
  let rebroadcast = cosigning.cosigns_to_rebroadcast();

  assert_eq!(
    rebroadcast.len(),
    1,
    "should only include faults, not cosigns from different sessions"
  );
  assert_eq!(rebroadcast[0].cosign.block_hash, faulty_hash);
  assert_eq!(rebroadcast[0].cosign.global_session, id);
}

#[test]
fn cosigns_to_rebroadcast_returns_latest_cosigns_when_not_faulted() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let block_hash = BlockHash([9u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
    txn.commit();
  }

  let cosign =
    Cosign { global_session: id, block_number, block_hash, cosigner: ExternalNetworkId::Bitcoin };
  let signed = sign_cosign(cosign, &keypair);

  let mut cosigning = Cosigning::new(db.clone());
  cosigning.intake_cosign(&signed).unwrap();

  let rebroadcast = cosigning.cosigns_to_rebroadcast();
  assert_eq!(rebroadcast.len(), 1);
  assert_eq!(rebroadcast[0].cosign.block_number, block_number);
  assert_eq!(rebroadcast[0].cosign.block_hash, block_hash);
}

#[test]
fn cosigns_to_rebroadcast_returns_faults_and_honest_when_faulted() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let our_hash = BlockHash([1u8; 32]);
  let faulty_hash = BlockHash([2u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &our_hash);
    txn.commit();
  }

  let faulty_cosign = Cosign {
    global_session: id,
    block_number,
    block_hash: faulty_hash,
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let faulty_signed = sign_cosign(faulty_cosign, &keypair);

  let mut cosigning = Cosigning::new(db.clone());
  cosigning.intake_cosign(&faulty_signed).unwrap();

  let honest_cosign = Cosign {
    global_session: id,
    block_number,
    block_hash: our_hash,
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let honest_signed = sign_cosign(honest_cosign, &keypair);
  {
    let mut txn = db.txn();
    NetworksLatestCosignedBlock::set(&mut txn, id, ExternalNetworkId::Bitcoin, &honest_signed);
    txn.commit();
  }

  let cosigning = Cosigning::new(db);
  let rebroadcast = cosigning.cosigns_to_rebroadcast();

  assert!(rebroadcast.iter().any(|c| c.cosign.block_hash == faulty_hash));
  assert!(rebroadcast.iter().any(|c| c.cosign.block_hash == our_hash));
}

#[test]
fn intake_cosign_rejects_not_yet_indexed_block() {
  let db = MemDb::new();
  let keypair = sr25519_fixture();

  let cosign = Cosign {
    global_session: [1u8; 32],
    block_number: 1,
    block_hash: BlockHash([9u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let signed = sign_cosign(cosign, &keypair);

  let mut cosigning = Cosigning::new(db);
  assert!(matches!(cosigning.intake_cosign(&signed), Err(IntakeCosignError::NotYetIndexedBlock)));
}

#[test]
fn intake_cosign_accepts_valid_cosign() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let block_hash = BlockHash([9u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
    txn.commit();
  }

  let cosign =
    Cosign { global_session: id, block_number, block_hash, cosigner: ExternalNetworkId::Bitcoin };
  let signed = sign_cosign(cosign, &keypair);

  let mut cosigning = Cosigning::new(db);
  assert!(cosigning.intake_cosign(&signed).is_ok());
}

#[test]
fn intake_cosign_rejects_stale_cosign() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_hash = BlockHash([9u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, 1, &block_hash);
    SubstrateBlockHash::set(&mut txn, 2, &BlockHash([2u8; 32]));
    txn.commit();
  }

  let first_cosign = Cosign {
    global_session: id,
    block_number: 2,
    block_hash: BlockHash([2u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let first_signed = sign_cosign(first_cosign, &keypair);

  let mut cosigning = Cosigning::new(db.clone());
  cosigning.intake_cosign(&first_signed).unwrap();

  let stale_cosign = Cosign {
    global_session: id,
    block_number: 1,
    block_hash,
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let stale_signed = sign_cosign(stale_cosign, &keypair);

  assert!(matches!(cosigning.intake_cosign(&stale_signed), Err(IntakeCosignError::StaleCosign)));
}

#[test]
fn intake_cosign_rejects_unrecognized_global_session() {
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  let block_number = 1;
  let block_hash = BlockHash([9u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
    txn.commit();
  }

  let cosign = Cosign {
    global_session: [99u8; 32],
    block_number,
    block_hash,
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let signed = sign_cosign(cosign, &keypair);

  let mut cosigning = Cosigning::new(db);
  assert!(matches!(
    cosigning.intake_cosign(&signed),
    Err(IntakeCosignError::UnrecognizedGlobalSession)
  ));
}

#[test]
fn intake_cosign_rejects_before_global_session_start() {
  let mut session = session_fixture();
  session.start_block_number = 10;
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  {
    let mut txn = db.txn();
    GlobalSessions::set(&mut txn, id, &session.to_global());
    CurrentlyEvaluatedGlobalSession::set(&mut txn, &(id, session.to_global()));
    LatestCosignedBlockNumber::set(&mut txn, &10u64);

    SubstrateBlockHash::set(&mut txn, 5, &BlockHash([5u8; 32]));
    txn.commit();
  }

  let cosign = Cosign {
    global_session: id,
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let signed = sign_cosign(cosign, &keypair);

  let mut cosigning = Cosigning::new(db);
  assert!(matches!(
    cosigning.intake_cosign(&signed),
    Err(IntakeCosignError::BeforeGlobalSessionStart)
  ));
}

#[test]
fn intake_cosign_rejects_after_global_session_end() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  {
    let mut txn = db.txn();

    GlobalSessionsLastBlock::set(&mut txn, id, &5u64);

    SubstrateBlockHash::set(&mut txn, 10, &BlockHash([10u8; 32]));
    txn.commit();
  }

  let cosign = Cosign {
    global_session: id,
    block_number: 10,
    block_hash: BlockHash([10u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let signed = sign_cosign(cosign, &keypair);

  let mut cosigning = Cosigning::new(db);
  assert!(matches!(
    cosigning.intake_cosign(&signed),
    Err(IntakeCosignError::AfterGlobalSessionEnd)
  ));
}

#[test]
fn intake_cosign_rejects_invalid_signature() {
  let session = session_fixture();
  let id = session.id();
  // Use a different keypair than the one in session_fixture
  let wrong_keypair = Sr25519Fixture { seed: [99u8; 32] };

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let block_hash = BlockHash([9u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
    txn.commit();
  }

  let cosign =
    Cosign { global_session: id, block_number, block_hash, cosigner: ExternalNetworkId::Bitcoin };
  let signed = sign_cosign(cosign, &wrong_keypair);

  let mut cosigning = Cosigning::new(db);
  assert!(matches!(cosigning.intake_cosign(&signed), Err(IntakeCosignError::InvalidSignature)));
}

#[test]
fn intake_cosign_rejects_future_global_session() {
  let mut session = session_fixture();
  session.start_block_number = 10;
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  {
    let mut txn = db.txn();
    GlobalSessions::set(&mut txn, id, &session.to_global());
    CurrentlyEvaluatedGlobalSession::set(&mut txn, &(id, session.to_global()));

    LatestCosignedBlockNumber::set(&mut txn, &5u64);
    SubstrateBlockHash::set(&mut txn, 10, &BlockHash([10u8; 32]));
    txn.commit();
  }

  let cosign = Cosign {
    global_session: id,
    block_number: 10,
    block_hash: BlockHash([10u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let signed = sign_cosign(cosign, &keypair);

  let mut cosigning = Cosigning::new(db);
  assert!(matches!(cosigning.intake_cosign(&signed), Err(IntakeCosignError::FutureGlobalSession)));
}

#[test]
fn intake_cosign_handles_faulty_cosign() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let our_hash = BlockHash([1u8; 32]);
  let faulty_hash = BlockHash([2u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &our_hash);
    txn.commit();
  }

  let cosign = Cosign {
    global_session: id,
    block_number,
    block_hash: faulty_hash,
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let signed = sign_cosign(cosign, &keypair);

  let mut cosigning = Cosigning::new(db.clone());

  assert!(cosigning.intake_cosign(&signed).is_ok());

  let faults: Option<Vec<SignedCosign>> = Faults::get(&db, id);
  assert!(faults.is_some());
  assert_eq!(faults.as_ref().unwrap().len(), 1);
  assert_eq!(faults.unwrap()[0].cosign.block_hash, faulty_hash);

  let faulted: Option<[u8; 32]> = FaultedSession::get(&db);
  assert_eq!(faulted, Some(id));
}

#[test]
fn intake_cosign_accepts_newer_cosign_when_existing_is_older() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, 1, &BlockHash([1u8; 32]));
    SubstrateBlockHash::set(&mut txn, 2, &BlockHash([2u8; 32]));
    txn.commit();
  }

  let first_cosign = Cosign {
    global_session: id,
    block_number: 1,
    block_hash: BlockHash([1u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let first_signed = sign_cosign(first_cosign, &keypair);

  let mut cosigning = Cosigning::new(db.clone());
  cosigning.intake_cosign(&first_signed).unwrap();

  let newer_cosign = Cosign {
    global_session: id,
    block_number: 2,
    block_hash: BlockHash([2u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let newer_signed = sign_cosign(newer_cosign, &keypair);

  assert!(cosigning.intake_cosign(&newer_signed).is_ok());

  let latest = NetworksLatestCosignedBlock::get(&db, id, ExternalNetworkId::Bitcoin).unwrap();
  assert_eq!(latest.cosign.block_number, 2);
}

#[test]
fn intake_cosign_accepts_cosign_at_global_session_last_block() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  {
    let mut txn = db.txn();
    GlobalSessionsLastBlock::set(&mut txn, id, &5u64);
    for i in 1..=5 {
      SubstrateBlockHash::set(&mut txn, i, &BlockHash([i as u8; 32]));
    }
    txn.commit();
  }

  let mut cosigning = Cosigning::new(db.clone());

  let cosign = Cosign {
    global_session: id,
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let signed = sign_cosign(cosign, &keypair);

  assert!(cosigning.intake_cosign(&signed).is_ok());

  let latest = NetworksLatestCosignedBlock::get(&db, id, ExternalNetworkId::Bitcoin).unwrap();
  assert_eq!(latest.cosign.block_number, 5);
}

#[test]
fn intake_cosign_ignores_duplicate_fault_from_same_network() {
  let session = session_fixture();
  let id = session.id();
  let keypair = sr25519_fixture();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let our_hash = BlockHash([1u8; 32]);
  let faulty_hash_1 = BlockHash([2u8; 32]);
  let faulty_hash_2 = BlockHash([3u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &our_hash);
    txn.commit();
  }

  let faulty_cosign_1 = Cosign {
    global_session: id,
    block_number,
    block_hash: faulty_hash_1,
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let faulty_signed_1 = sign_cosign(faulty_cosign_1, &keypair);

  let mut cosigning = Cosigning::new(db.clone());
  assert!(cosigning.intake_cosign(&faulty_signed_1).is_ok());

  let faults_after_first = Faults::get(&db, id).unwrap();
  assert_eq!(faults_after_first.len(), 1);
  assert_eq!(faults_after_first[0].cosign.block_hash, faulty_hash_1);

  let faulty_cosign_2 = Cosign {
    global_session: id,
    block_number,
    block_hash: faulty_hash_2,
    cosigner: ExternalNetworkId::Bitcoin,
  };
  let faulty_signed_2 = sign_cosign(faulty_cosign_2, &keypair);

  assert!(cosigning.intake_cosign(&faulty_signed_2).is_ok());

  let faults_after_second = Faults::get(&db, id).unwrap();
  assert_eq!(faults_after_second.len(), 1, "duplicate fault from same network should not be added");
  assert_eq!(faults_after_second[0].cosign.block_hash, faulty_hash_1);
}

#[test]
fn intake_cosign_rejects_non_participating_network() {
  let session = session_fixture();
  let id = session.id();

  let eth_keypair = Sr25519Fixture { seed: [77u8; 32] };

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let block_hash = BlockHash([9u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
    txn.commit();
  }

  let cosign =
    Cosign { global_session: id, block_number, block_hash, cosigner: ExternalNetworkId::Ethereum };
  let signed = sign_cosign(cosign, &eth_keypair);

  let mut cosigning = Cosigning::new(db);
  assert!(matches!(
    cosigning.intake_cosign(&signed),
    Err(IntakeCosignError::NonParticipatingNetwork)
  ));
}

#[test]
fn intake_cosign_records_fault_below_threshold() {
  let network1 = ExternalNetworkId::Bitcoin;
  let network2 = ExternalNetworkId::Ethereum;
  let set1 = ExternalValidatorSet { network: network1, session: Session(0) };
  let set2 = ExternalValidatorSet { network: network2, session: Session(0) };

  let keypair1 = sr25519_fixture();
  let keypair2 = Sr25519Fixture { seed: [88u8; 32] };

  let mut keys = HashMap::new();
  let mut stakes = HashMap::new();

  keys.insert(network1, Public(keypair1.public_bytes()));
  keys.insert(network2, Public(keypair2.public_bytes()));

  stakes.insert(network1, 10);
  stakes.insert(network2, 90);

  let session = TestGlobalSession {
    start_block_number: 1,
    sets: vec![set1, set2],
    keys,
    stakes,
    total_stake: 100,
  };
  let id = session.id();

  let mut db = MemDb::new();
  seed_minimal_state(&mut db, &session);

  let block_number = 1;
  let our_hash = BlockHash([1u8; 32]);
  let faulty_hash = BlockHash([2u8; 32]);
  {
    let mut txn = db.txn();
    SubstrateBlockHash::set(&mut txn, block_number, &our_hash);
    txn.commit();
  }

  let faulty_cosign =
    Cosign { global_session: id, block_number, block_hash: faulty_hash, cosigner: network1 };
  let faulty_signed = sign_cosign(faulty_cosign, &keypair1);

  let mut cosigning = Cosigning::new(db.clone());
  assert!(cosigning.intake_cosign(&faulty_signed).is_ok());

  let faults = Faults::get(&db, id).unwrap();
  assert_eq!(faults.len(), 1);
  assert_eq!(faults[0].cosign.block_hash, faulty_hash);

  let faulted = FaultedSession::get(&db);
  assert_eq!(faulted, None, "session should not be faulted when weight is below 17% threshold");
}

#[test]
fn intended_cosigns_empty_returns_empty() {
  let mut db = MemDb::new();
  let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let mut txn = db.txn();
  assert!(Cosigning::<MemDb>::intended_cosigns(&mut txn, set).is_empty());
  txn.commit();
}

#[test]
fn intended_cosigns_receives_sent_intent() {
  let mut db = MemDb::new();
  let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };

  let intent = CosignIntent {
    global_session: [1u8; 32],
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    notable: true,
  };

  {
    let mut txn = db.txn();
    IntendedCosigns::send(&mut txn, set, &intent);
    txn.commit();
  }

  {
    let mut txn = db.txn();
    let got = Cosigning::<MemDb>::intended_cosigns(&mut txn, set);
    txn.commit();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].global_session, intent.global_session);
    assert_eq!(got[0].block_number, intent.block_number);
    assert_eq!(got[0].block_hash, intent.block_hash);
    assert!(got[0].notable);
  }
}
