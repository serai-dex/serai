use crate::{delay::*, evaluator::*, intend::*, tests::*, *};

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
    GlobalSession::id(self.sets.clone())
  }

  fn to_global_session(&self) -> GlobalSession {
    GlobalSession {
      start_block_number: self.start_block_number,
      sets: self.sets.clone(),
      keys: self.keys.clone(),
      stakes: self.stakes.clone(),
      total_stake: self.total_stake,
    }
  }
}

fn random_test_session() -> (TestGlobalSession, schnorrkel::Keypair) {
  let set = default_test_validator_set();
  let (keypair, public) = random_keypair(&mut OsRng);
  let stake = OsRng.gen_range(1u64 .. u64::MAX / 17);
  let gs = build_global_session(set, public, stake, u64::from(set.session.0) + 1);

  let session = TestGlobalSession {
    start_block_number: gs.start_block_number,
    sets: gs.sets,
    keys: gs.keys,
    stakes: gs.stakes,
    total_stake: gs.total_stake,
  };
  (session, keypair)
}

fn seed_minimal_state(db: &mut MemDb, random_test_session: &TestGlobalSession) {
  let mut txn = db.txn();
  let id = random_test_session.id();

  // Required by `Cosigning::intake_cosign`.
  GlobalSessions::set(&mut txn, id, &random_test_session.to_global_session());

  // Required by `Cosigning::cosigns_to_rebroadcast` in the non-faulted case.
  CurrentlyEvaluatedGlobalSession::set(&mut txn, &(id, random_test_session.to_global_session()));

  // Required for `intake_cosign` to not classify a session as "future".
  LatestCosignedBlockNumber::set(&mut txn, &0u64);

  txn.commit();
}

#[test]
fn fuzz_global_session_id() {
  for _ in 0 .. 100 {
    let num_sets = OsRng.gen_range(1u8 ..= 3);
    let sets: Vec<_> = (0 .. num_sets).map(|_| random_validator_set(&mut OsRng)).collect();

    let id1 = GlobalSession::id(sets.clone());
    let id2 = GlobalSession::id(sets.clone());

    // Determinism: same input always produces same ID
    assert_eq!(id1, id2);

    // Order-independence: any permutation produces the same ID
    let mut reversed = sets.clone();
    reversed.reverse();
    assert_eq!(id1, GlobalSession::id(reversed));

    // Collision resistance: changing any set should change the ID
    let mut altered = sets.clone();
    altered[0] = random_validator_set(&mut OsRng);
    if altered != sets {
      assert_ne!(id1, GlobalSession::id(altered));
    }
  }
}

mod intake_cosign_error {
  use super::*;

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
}

// More cases are tested in ./full_stack.rs with fuzzing for different event type blocks
#[tokio::test]
async fn spawn_end_to_end() {
  let db = MemDb::new();
  let (shim_serai, serai) = setup_shim_serai().await;
  let (request, _calls) = TestRequest::new(false);

  /// Create a trivial task that logs and sets a flag when triggered whose handle is passed to the cosigning pipeline.
  struct LogOnTrigger(Arc<AtomicBool>);
  impl ContinuallyRan for LogOnTrigger {
    type Error = std::convert::Infallible;
    fn run_iteration(
      &mut self,
    ) -> impl Send + std::future::Future<Output = Result<bool, Self::Error>> {
      async {
        serai_env::info!("dependent task triggered by cosigning pipeline");
        self.0.store(true, Ordering::SeqCst);
        Ok(false)
      }
    }
  }
  let (dependent_task, dependent_handle) = Task::new();
  let triggered = Arc::new(AtomicBool::new(false));
  tokio::spawn(LogOnTrigger(triggered.clone()).continually_run(dependent_task, vec![]));

  // Spawn cosigning tasks with the dependent task handle
  let cosigning = Cosigning::spawn(db.clone(), serai, request, vec![dependent_handle]);

  // Just started: results are empty
  {
    assert!(cosigning.cosigns_to_rebroadcast().is_empty());
    let latest = Cosigning::<MemDb>::latest_cosigned_block_number(&db);
    assert!(latest.is_ok());
    assert_eq!(latest.unwrap(), None);
  }

  // Run block production and pipeline polling concurrently
  let total_blocks = 10;
  tokio::join!(
    // Produce blocks with no events (passes all tasks and is marked as cosigned at the end)
    async {
      for _ in 0 ..= total_blocks {
        shim_serai.add_block_with_events(vec![]).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
    },
    // Poll until the pipeline has processed all blocks
    async {
      loop {
        let latest = Cosigning::<MemDb>::latest_cosigned_block_number(&db);
        if latest.ok().flatten().is_some_and(|n| n >= total_blocks) {
          break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
    }
  );

  let latest = Cosigning::<MemDb>::latest_cosigned_block_number(&db).unwrap();
  assert_eq!(latest, Some(total_blocks));

  // Verify the dependent task was triggered by the cosign pipeline
  assert!(triggered.load(Ordering::SeqCst));
}

#[test]
fn latest_finalized_block() {
  // Defaults to zero
  {
    let db = MemDb::new();
    assert_eq!(Cosigning::<MemDb>::latest_cosigned_block_number(&db).unwrap(), None);
  }

  // Errors when faulted session exists
  {
    let mut db = MemDb::new();
    {
      let mut txn = db.txn();
      FaultedSession::set(&mut txn, &random_global_session(&mut OsRng));
      txn.commit();
    }
    assert!(matches!(Cosigning::<MemDb>::latest_cosigned_block_number(&db), Err(Faulted)));
  }

  // Returns stored value
  {
    let mut db = MemDb::new();
    let latest_finalized_block = OsRng.next_u64();
    {
      let mut txn = db.txn();
      LatestCosignedBlockNumber::set(&mut txn, &latest_finalized_block);
      txn.commit();
    }
    assert_eq!(
      Cosigning::<MemDb>::latest_cosigned_block_number(&db).unwrap(),
      Some(latest_finalized_block)
    );
  }
}

#[test]
fn cosigned_block() {
  // Returns None beyond latest finalized block
  {
    let mut db = MemDb::new();
    assert_eq!(Cosigning::<MemDb>::cosigned_block(&db, 0).unwrap(), None);

    let latest_finalized_block = OsRng.next_u64();
    {
      let mut txn = db.txn();
      LatestCosignedBlockNumber::set(&mut txn, &latest_finalized_block);
      txn.commit();
    }
    assert_eq!(Cosigning::<MemDb>::cosigned_block(&db, latest_finalized_block + 1).unwrap(), None);
  }

  // Returns hash when block is in range
  {
    let mut db = MemDb::new();
    let latest_finalized_block = OsRng.next_u64();
    let block_hash = random_block_hash(&mut OsRng);
    {
      let mut txn = db.txn();
      LatestCosignedBlockNumber::set(&mut txn, &latest_finalized_block);
      SubstrateBlockHash::set(&mut txn, latest_finalized_block - 1, &block_hash);
      txn.commit();
    }
    assert_eq!(
      Cosigning::<MemDb>::cosigned_block(&db, latest_finalized_block - 1).unwrap(),
      Some(block_hash)
    );
  }

  // Errors when faulted session exists
  {
    let mut db = MemDb::new();
    {
      let mut txn = db.txn();
      FaultedSession::set(&mut txn, &random_global_session(&mut OsRng));
      txn.commit();
    }
    assert!(matches!(Cosigning::<MemDb>::cosigned_block(&db, OsRng.next_u64()), Err(Faulted)));
  }
}

#[test]
fn notable_cosigns() {
  // Empty without cosigns
  {
    let db = MemDb::new();
    let cosigns = Cosigning::<MemDb>::notable_cosigns(&db, random_global_session(&mut OsRng));
    assert!(cosigns.is_empty());
  }

  // Returns cosigns for session
  {
    let (session, keypair) = random_test_session();
    let id = session.id();
    let network = session.sets[0].network;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number = OsRng.next_u64();
    let block_hash = random_block_hash(&mut OsRng);
    {
      let mut txn = db.txn();
      SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
      txn.commit();
    }

    let cosign = Cosign { global_session: id, block_number, block_hash, cosigner: network };
    let signed = sign_cosign(cosign, &keypair);

    let mut cosigning = Cosigning::new(db.clone());
    cosigning.intake_cosign(&signed).unwrap();

    let notable = Cosigning::<MemDb>::notable_cosigns(&db, id);
    assert_eq!(notable.len(), 1);

    let SignedCosign { cosign, .. } = &notable[0];
    let Cosign {
      global_session,
      block_number: cosign_block_number,
      block_hash: cosign_block_hash,
      cosigner,
    } = cosign;
    assert_eq!(global_session, &id);
    assert_eq!(cosign_block_number, &block_number);
    assert_eq!(cosign_block_hash, &block_hash);
    assert_eq!(cosigner, &network);
  }
}

#[test]
fn cosigns_to_rebroadcast() {
  // Excludes cosigns from different global session
  {
    let (session, keypair) = random_test_session();
    let id = session.id();
    let network = session.sets[0].network;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number = OsRng.next_u64();
    let our_hash = random_block_hash(&mut OsRng);
    let faulty_hash = random_block_hash(&mut OsRng);
    {
      let mut txn = db.txn();
      SubstrateBlockHash::set(&mut txn, block_number, &our_hash);
      txn.commit();
    }

    let faulty_cosign =
      Cosign { global_session: id, block_number, block_hash: faulty_hash, cosigner: network };
    let faulty_signed = sign_cosign(faulty_cosign, &keypair);

    let mut cosigning = Cosigning::new(db.clone());
    cosigning.intake_cosign(&faulty_signed).unwrap();

    let different_session_id = random_global_session(&mut OsRng);
    let different_cosign = Cosign {
      global_session: different_session_id,
      block_number,
      block_hash: our_hash,
      cosigner: network,
    };
    let different_signed = sign_cosign(different_cosign, &keypair);
    {
      let mut txn = db.txn();
      NetworksLatestCosignedBlock::set(&mut txn, id, network, &different_signed);
      txn.commit();
    }

    let cosigning = Cosigning::new(db);
    let rebroadcast = cosigning.cosigns_to_rebroadcast();

    assert_eq!(rebroadcast.len(), 1,);
    assert_eq!(rebroadcast[0].cosign.block_hash, faulty_hash);
    assert_eq!(rebroadcast[0].cosign.global_session, id);
  }

  // Returns latest cosigns when not faulted
  {
    let (session, keypair) = random_test_session();
    let id = session.id();
    let network = session.sets[0].network;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number = OsRng.next_u64();
    let block_hash = random_block_hash(&mut OsRng);
    {
      let mut txn = db.txn();
      SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
      txn.commit();
    }

    let cosign = Cosign { global_session: id, block_number, block_hash, cosigner: network };
    let signed = sign_cosign(cosign, &keypair);

    let mut cosigning = Cosigning::new(db.clone());
    cosigning.intake_cosign(&signed).unwrap();

    let rebroadcast = cosigning.cosigns_to_rebroadcast();
    assert_eq!(rebroadcast.len(), 1);
    assert_eq!(rebroadcast[0].cosign.block_number, block_number);
    assert_eq!(rebroadcast[0].cosign.block_hash, block_hash);
  }

  // Returns faults and honest cosigns when faulted
  {
    let (session, keypair) = random_test_session();
    let id = session.id();
    let network = session.sets[0].network;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number = OsRng.next_u64();
    let our_hash = random_block_hash(&mut OsRng);
    let faulty_hash = random_block_hash(&mut OsRng);
    {
      let mut txn = db.txn();
      SubstrateBlockHash::set(&mut txn, block_number, &our_hash);
      txn.commit();
    }

    let faulty_cosign =
      Cosign { global_session: id, block_number, block_hash: faulty_hash, cosigner: network };
    let faulty_signed = sign_cosign(faulty_cosign, &keypair);

    let mut cosigning = Cosigning::new(db.clone());
    cosigning.intake_cosign(&faulty_signed).unwrap();

    let honest_cosign =
      Cosign { global_session: id, block_number, block_hash: our_hash, cosigner: network };
    let honest_signed = sign_cosign(honest_cosign, &keypair);
    {
      let mut txn = db.txn();
      NetworksLatestCosignedBlock::set(&mut txn, id, network, &honest_signed);
      txn.commit();
    }

    let cosigning = Cosigning::new(db);
    let rebroadcast = cosigning.cosigns_to_rebroadcast();

    assert!(rebroadcast.iter().any(|c| c.cosign.block_hash == faulty_hash));
    assert!(rebroadcast.iter().any(|c| c.cosign.block_hash == our_hash));
  }
}

mod intake_cosign {
  use super::*;

  mod errors {
    use super::*;

    #[test]
    fn rejects_not_yet_indexed_block() {
      let db = MemDb::new();
      let (keypair, _) = random_keypair(&mut OsRng);

      let signed = sign_cosign(random_cosign(&mut OsRng), &keypair);

      let mut cosigning = Cosigning::new(db);
      assert!(matches!(
        cosigning.intake_cosign(&signed),
        Err(IntakeCosignError::NotYetIndexedBlock)
      ));
    }

    #[test]
    fn rejects_stale_cosign() {
      let (session, keypair) = random_test_session();
      let id = session.id();
      let network = session.sets[0].network;

      let mut db = MemDb::new();
      seed_minimal_state(&mut db, &session);

      let base_block = OsRng.next_u64() / 2;
      let block_hash_1 = random_block_hash(&mut OsRng);
      let block_hash_2 = random_block_hash(&mut OsRng);
      {
        let mut txn = db.txn();
        SubstrateBlockHash::set(&mut txn, base_block, &block_hash_1);
        SubstrateBlockHash::set(&mut txn, base_block + 1, &block_hash_2);
        txn.commit();
      }

      let first_cosign = Cosign {
        global_session: id,
        block_number: base_block + 1,
        block_hash: block_hash_2,
        cosigner: network,
      };
      let first_signed = sign_cosign(first_cosign, &keypair);

      let mut cosigning = Cosigning::new(db.clone());
      cosigning.intake_cosign(&first_signed).unwrap();

      let stale_cosign = Cosign {
        global_session: id,
        block_number: base_block,
        block_hash: block_hash_1,
        cosigner: network,
      };
      let stale_signed = sign_cosign(stale_cosign, &keypair);

      assert!(matches!(
        cosigning.intake_cosign(&stale_signed),
        Err(IntakeCosignError::StaleCosign)
      ));
    }

    #[test]
    fn rejects_unrecognized_global_session() {
      let (keypair, _) = random_keypair(&mut OsRng);

      let mut db = MemDb::new();
      let block_number = OsRng.next_u64();
      let block_hash = random_block_hash(&mut OsRng);
      {
        let mut txn = db.txn();
        SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
        txn.commit();
      }

      let cosign = Cosign {
        global_session: random_global_session(&mut OsRng),
        block_number,
        block_hash,
        cosigner: random_validator_set(&mut OsRng).network,
      };
      let signed = sign_cosign(cosign, &keypair);

      let mut cosigning = Cosigning::new(db);
      assert!(matches!(
        cosigning.intake_cosign(&signed),
        Err(IntakeCosignError::UnrecognizedGlobalSession)
      ));
    }

    #[test]
    fn rejects_before_global_session_start() {
      let (mut session, keypair) = random_test_session();
      let network = session.sets[0].network;
      session.start_block_number = OsRng.next_u64();
      let id = session.id();

      let block_hash = random_block_hash(&mut OsRng);
      let mut db = MemDb::new();
      {
        let mut txn = db.txn();
        GlobalSessions::set(&mut txn, id, &session.to_global_session());
        CurrentlyEvaluatedGlobalSession::set(&mut txn, &(id, session.to_global_session()));
        LatestCosignedBlockNumber::set(&mut txn, &session.start_block_number);
        SubstrateBlockHash::set(&mut txn, session.start_block_number - 1, &block_hash);
        txn.commit();
      }

      let cosign = Cosign {
        global_session: id,
        block_number: session.start_block_number - 1,
        block_hash,
        cosigner: network,
      };
      let signed = sign_cosign(cosign, &keypair);

      let mut cosigning = Cosigning::new(db);
      assert!(matches!(
        cosigning.intake_cosign(&signed),
        Err(IntakeCosignError::BeforeGlobalSessionStart)
      ));
    }

    #[test]
    fn rejects_after_global_session_end() {
      let (session, keypair) = random_test_session();
      let id = session.id();
      let network = session.sets[0].network;

      let mut db = MemDb::new();
      seed_minimal_state(&mut db, &session);

      let block_hash = random_block_hash(&mut OsRng);
      let block_number = OsRng.next_u64();
      {
        let mut txn = db.txn();
        GlobalSessionsLastBlock::set(&mut txn, id, &(block_number - 1));
        SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
        txn.commit();
      }

      let cosign = Cosign { global_session: id, block_number, block_hash, cosigner: network };
      let signed = sign_cosign(cosign, &keypair);

      let mut cosigning = Cosigning::new(db);
      assert!(matches!(
        cosigning.intake_cosign(&signed),
        Err(IntakeCosignError::AfterGlobalSessionEnd)
      ));
    }

    #[test]
    fn rejects_invalid_signature() {
      let (session, _keypair) = random_test_session();
      let id = session.id();
      let network = session.sets[0].network;
      let (wrong_keypair, _) = random_keypair(&mut OsRng);

      let mut db = MemDb::new();
      seed_minimal_state(&mut db, &session);

      let block_number = OsRng.next_u64();
      let block_hash = random_block_hash(&mut OsRng);
      {
        let mut txn = db.txn();
        SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
        txn.commit();
      }

      let cosign = Cosign { global_session: id, block_number, block_hash, cosigner: network };
      let signed = sign_cosign(cosign, &wrong_keypair);

      let mut cosigning = Cosigning::new(db);
      assert!(matches!(cosigning.intake_cosign(&signed), Err(IntakeCosignError::InvalidSignature)));
    }

    #[test]
    fn rejects_future_global_session() {
      let (mut session, keypair) = random_test_session();
      let network = session.sets[0].network;
      session.start_block_number = OsRng.next_u64();
      let id = session.id();

      let block_hash = random_block_hash(&mut OsRng);
      let mut db = MemDb::new();
      {
        let mut txn = db.txn();
        GlobalSessions::set(&mut txn, id, &session.to_global_session());
        CurrentlyEvaluatedGlobalSession::set(&mut txn, &(id, session.to_global_session()));
        LatestCosignedBlockNumber::set(&mut txn, &(session.start_block_number - 2));
        SubstrateBlockHash::set(&mut txn, session.start_block_number, &block_hash);
        txn.commit();
      }

      let cosign = Cosign {
        global_session: id,
        block_number: session.start_block_number,
        block_hash,
        cosigner: network,
      };
      let signed = sign_cosign(cosign, &keypair);

      let mut cosigning = Cosigning::new(db);
      assert!(matches!(
        cosigning.intake_cosign(&signed),
        Err(IntakeCosignError::FutureGlobalSession)
      ));
    }

    #[test]
    fn rejects_non_participating_network() {
      let (session, _keypair) = random_test_session();
      let id = session.id();
      let session_network = session.sets[0].network;

      let non_participating = ExternalNetworkId::all().find(|n| *n != session_network).unwrap();
      let (other_keypair, _) = random_keypair(&mut OsRng);

      let mut db = MemDb::new();
      seed_minimal_state(&mut db, &session);

      let block_number = OsRng.next_u64();
      let block_hash = random_block_hash(&mut OsRng);
      {
        let mut txn = db.txn();
        SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
        txn.commit();
      }

      let cosign =
        Cosign { global_session: id, block_number, block_hash, cosigner: non_participating };
      let signed = sign_cosign(cosign, &other_keypair);

      let mut cosigning = Cosigning::new(db);
      assert!(matches!(
        cosigning.intake_cosign(&signed),
        Err(IntakeCosignError::NonParticipatingNetwork)
      ));
    }
  }

  #[test]
  fn accepts_valid_cosign() {
    let (session, keypair) = random_test_session();
    let id = session.id();
    let network = session.sets[0].network;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number = OsRng.next_u64();
    let block_hash = random_block_hash(&mut OsRng);
    {
      let mut txn = db.txn();
      SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
      txn.commit();
    }

    let cosign = Cosign { global_session: id, block_number, block_hash, cosigner: network };
    let signed = sign_cosign(cosign, &keypair);

    let mut cosigning = Cosigning::new(db);
    assert!(cosigning.intake_cosign(&signed).is_ok());
  }

  #[test]
  fn handles_faulty_cosign() {
    let (session, keypair) = random_test_session();
    let id = session.id();
    let network = session.sets[0].network;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number = OsRng.next_u64();
    let our_hash = random_block_hash(&mut OsRng);
    let faulty_hash = random_block_hash(&mut OsRng);
    {
      let mut txn = db.txn();
      SubstrateBlockHash::set(&mut txn, block_number, &our_hash);
      txn.commit();
    }

    let cosign =
      Cosign { global_session: id, block_number, block_hash: faulty_hash, cosigner: network };
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
  fn accepts_newer_cosign_when_existing_is_older() {
    let (session, keypair) = random_test_session();
    let id = session.id();
    let network = session.sets[0].network;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number1 = OsRng.next_u64();
    let block_hash_1 = random_block_hash(&mut OsRng);
    let block_number2 = block_number1 + 1;
    let block_hash_2 = random_block_hash(&mut OsRng);
    {
      let mut txn = db.txn();
      SubstrateBlockHash::set(&mut txn, block_number1, &block_hash_1);
      SubstrateBlockHash::set(&mut txn, block_number2, &block_hash_2);
      txn.commit();
    }

    let first_cosign = Cosign {
      global_session: id,
      block_number: block_number1,
      block_hash: block_hash_1,
      cosigner: network,
    };
    let first_signed = sign_cosign(first_cosign, &keypair);

    let mut cosigning = Cosigning::new(db.clone());
    cosigning.intake_cosign(&first_signed).unwrap();

    let newer_cosign = Cosign {
      global_session: id,
      block_number: block_number2,
      block_hash: block_hash_2,
      cosigner: network,
    };
    let newer_signed = sign_cosign(newer_cosign, &keypair);

    assert!(cosigning.intake_cosign(&newer_signed).is_ok());

    let latest = NetworksLatestCosignedBlock::get(&db, id, network).unwrap();
    assert_eq!(latest.cosign.block_number, block_number2);
  }

  #[test]
  fn accepts_cosign_at_global_session_last_block() {
    let (session, keypair) = random_test_session();
    let id = session.id();
    let network = session.sets[0].network;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let last_block = u64::from(OsRng.next_u32() % 100) + 1; // any from 1 to 100
    let mut block_hashes = Vec::new();
    {
      let mut txn = db.txn();
      GlobalSessionsLastBlock::set(&mut txn, id, &last_block);
      for i in 1 ..= last_block {
        let hash = random_block_hash(&mut OsRng);
        SubstrateBlockHash::set(&mut txn, i, &hash);
        block_hashes.push(hash);
      }
      txn.commit();
    }

    let mut cosigning = Cosigning::new(db.clone());

    let cosign = Cosign {
      global_session: id,
      block_number: last_block,
      block_hash: block_hashes[last_block as usize - 1],
      cosigner: network,
    };
    let signed = sign_cosign(cosign, &keypair);

    assert!(cosigning.intake_cosign(&signed).is_ok());

    let latest = NetworksLatestCosignedBlock::get(&db, id, network).unwrap();
    assert_eq!(latest.cosign.block_number, last_block);
  }

  #[test]
  fn ignores_duplicate_fault_from_same_network() {
    let (session, keypair) = random_test_session();
    let id = session.id();
    let network = session.sets[0].network;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number = OsRng.next_u64();
    let our_hash = random_block_hash(&mut OsRng);
    let faulty_hash_1 = random_block_hash(&mut OsRng);
    let faulty_hash_2 = random_block_hash(&mut OsRng);
    {
      let mut txn = db.txn();
      SubstrateBlockHash::set(&mut txn, block_number, &our_hash);
      txn.commit();
    }

    let faulty_cosign_1 =
      Cosign { global_session: id, block_number, block_hash: faulty_hash_1, cosigner: network };
    let faulty_signed_1 = sign_cosign(faulty_cosign_1, &keypair);

    let mut cosigning = Cosigning::new(db.clone());
    assert!(cosigning.intake_cosign(&faulty_signed_1).is_ok());

    let faults_after_first = Faults::get(&db, id).unwrap();
    assert_eq!(faults_after_first.len(), 1);
    assert_eq!(faults_after_first[0].cosign.block_hash, faulty_hash_1);

    let faulty_cosign_2 =
      Cosign { global_session: id, block_number, block_hash: faulty_hash_2, cosigner: network };
    let faulty_signed_2 = sign_cosign(faulty_cosign_2, &keypair);

    assert!(cosigning.intake_cosign(&faulty_signed_2).is_ok());

    let faults_after_second = Faults::get(&db, id).unwrap();
    assert_eq!(
      faults_after_second.len(),
      1,
      "duplicate fault from same network should not be added"
    );
    assert_eq!(faults_after_second[0].cosign.block_hash, faulty_hash_1);
  }

  #[test]
  fn records_fault_below_threshold() {
    let set1 = random_validator_set(&mut OsRng);
    let network1 = set1.network;
    // Ensure we pick a distinct second network
    let network2 = ExternalNetworkId::all().find(|n| *n != network1).unwrap();
    let set2 = ExternalValidatorSet { network: network2, session: Session(OsRng.next_u32()) };

    let (keypair1, public1) = random_keypair(&mut OsRng);
    let (_, public2) = random_keypair(&mut OsRng);

    let mut keys = HashMap::new();
    let mut stakes = HashMap::new();

    keys.insert(network1, public1);
    keys.insert(network2, public2);

    // stake1 must be below the 17% threshold: stake1 < (total_stake * 17) / 100
    let total_stake = OsRng.gen_range(100u64 .. 10_000);
    let max_below_threshold = (total_stake * 17) / 100;
    let stake1 = OsRng.gen_range(1 .. max_below_threshold.max(2));
    let stake2 = total_stake - stake1;

    stakes.insert(network1, stake1);
    stakes.insert(network2, stake2);

    let session = TestGlobalSession {
      start_block_number: u64::from(set1.session.0) + 1,
      sets: vec![set1, set2],
      keys,
      stakes,
      total_stake,
    };
    let id = session.id();

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number = OsRng.next_u64();
    let our_hash = random_block_hash(&mut OsRng);
    let faulty_hash = random_block_hash(&mut OsRng);
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
}

#[test]
fn intended_cosigns() {
  // Empty returns empty
  {
    let mut db = MemDb::new();
    let set = random_validator_set(&mut OsRng);
    let mut txn = db.txn();
    assert!(Cosigning::<MemDb>::intended_cosigns(&mut txn, set).is_empty());
    txn.commit();
  }

  // Receives sent intent
  {
    let mut db = MemDb::new();
    let set = random_validator_set(&mut OsRng);
    let intent = random_cosign_intent(&mut OsRng);

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
      assert_eq!(got[0].notable, intent.notable);
    }
  }
}
