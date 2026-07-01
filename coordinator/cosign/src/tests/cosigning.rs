use crate::{intend, evaluator, tests::*, test_helpers::*, *};

#[test]
fn constants() {
  assert_eq!(COSIGN_FAULT_THRESHOLD_NUMERATOR, 17);
  assert_eq!(COSIGN_FAULT_THRESHOLD_DENOMINATOR, 100);
  const {
    assert!(COSIGN_FAULT_THRESHOLD_NUMERATOR < COSIGN_FAULT_THRESHOLD_DENOMINATOR);
    assert!(
      // 17 + 83 = 100
      COSIGN_FAULT_THRESHOLD_NUMERATOR + evaluator::COSIGN_COMMIT_THRESHOLD_NUMERATOR ==
        evaluator::COSIGN_COMMIT_THRESHOLD_DENOMINATOR
    );
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

#[test]
fn cosign_fault_threshold_formula() {
  let mut rng = new_test_rng();
  for _ in 0 .. 100 {
    let total_stake = rng.gen_range(1u64 .. u64::MAX / 17);
    let fault = cosign_fault_threshold(total_stake);
    let expected = u64::try_from((u128::from(total_stake) * 17) / 100).expect("threshold < 1") + 1;
    assert_eq!(fault, expected, "mismatch for total_stake={total_stake}");
  }
}

fn random_global_cosigning_session<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> (GlobalCosigningSession, HashMap<ExternalNetworkId, schnorrkel::Keypair>) {
  let sets = random_external_validator_sets(rng);

  let mut keys = HashMap::with_capacity(sets.len());
  let mut stakes = HashMap::with_capacity(sets.len());
  let mut keypairs = HashMap::with_capacity(sets.len());
  let mut total_stake = 0u64;
  for set in &sets {
    let (keypair, public) = random_schnorrkel_keypair(rng);
    keys.insert(set.network, public);
    keypairs.insert(set.network, keypair);
    let stake = rng.gen_range(1u64 .. u64::MAX / 17);
    stakes.insert(set.network, stake);
    total_stake += stake;
  }

  (
    GlobalCosigningSession {
      start_block_number: rng.next_u64(),
      cosigning_sets: sets,
      keys,
      stakes,
      total_stake,
    },
    keypairs,
  )
}

fn seed_minimal_state(db: &mut MemDb, global_cosigning_session: &GlobalCosigningSession) {
  let mut txn = db.txn();
  let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

  // Required by `Cosigning::intake_cosign`.
  GlobalCosigningSessions::set(&mut txn, id, global_cosigning_session);

  // Required by `Cosigning::cosigns_to_rebroadcast` in the non-faulted case.
  evaluator::CurrentGlobalCosigningSessionEvaluator::set(
    &mut txn,
    &(id, global_cosigning_session.clone()),
  );

  // Required for `intake_cosign` to not classify a session as "future".
  // Set to the block before the session starts (i.e., the session's declaration block
  // has been cosigned), so the FutureGlobalSession check in intake_cosign passes.
  set_latest_cosigned_block_number(&mut txn, &(global_cosigning_session.start_block_number - 1));

  txn.commit();
}

#[test]
fn fuzz_global_cosigning_session_id() {
  let mut rng = new_test_rng();
  for _ in 0 .. 100 {
    let sets = random_external_validator_sets(&mut rng);

    let id1 = GlobalCosigningSession::id(sets.clone());
    let id2 = GlobalCosigningSession::id(sets.clone());

    // Determinism: same input always produces same ID
    assert_eq!(id1, id2);

    // Order-independence: any permutation produces the same ID
    {
      let mut shuffled = sets.clone();
      shuffled.shuffle(&mut rng);
      assert_eq!(id1, GlobalCosigningSession::id(shuffled));
    }

    // Collision resistance: changing any set should change the ID
    {
      let mut altered = sets.clone();
      while altered[0] == sets[0] {
        altered[0] = random_external_validator_set(&mut rng);
      }
      assert_ne!(id1, GlobalCosigningSession::id(altered));
    }
  }
}

// More cases are tested in `tests/full_stack.rs` with fuzzing for different event type blocks
#[tokio::test]
async fn spawn_end_to_end() {
  let mut _rng = new_test_rng();

  let db = MemDb::new();
  let (mock_serai, serai) = serai_mock_rpc::MockSeraiRpc::setup_mock_serai().await;
  let (request, _calls) = TestRequest::new(false);

  /// Create a trivial task that logs and sets a flag when triggered whose handle is passed to the
  /// cosigning pipeline.
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
  let cosigning = Cosigning::spawn_with_handles(db.clone(), serai, request, vec![dependent_handle]);

  // Just started: results are empty
  {
    assert!(cosigning.cosigns_to_rebroadcast().is_empty());
    let latest = Cosigning::<MemDb>::latest_cosigned_block_number(&db);
    assert_eq!(latest.unwrap(), None);
  }

  // Run block production and pipeline polling concurrently
  let total_blocks = 10;
  tokio::join!(
    // Produce blocks with no events (passes all tasks and is marked as cosigned at the end)
    async {
      for _ in 0 ..= total_blocks {
        mock_serai.add_block_with_events(vec![]).await;
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
fn latest_cosigned_block_number() {
  let mut rng = new_test_rng();
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
      set_faulted_session(&mut txn, &random_global_cosigning_session_id(&mut rng));
      txn.commit();
    }
    assert!(matches!(Cosigning::<MemDb>::latest_cosigned_block_number(&db), Err(Faulted)));
  }

  // Returns stored value
  {
    let mut db = MemDb::new();
    let latest_finalized_block = rng.next_u64();
    {
      let mut txn = db.txn();
      set_latest_cosigned_block_number(&mut txn, &latest_finalized_block);
      txn.commit();
    }
    assert_eq!(
      Cosigning::<MemDb>::latest_cosigned_block_number(&db).unwrap(),
      Some(latest_finalized_block)
    );
  }
}

#[test]
fn get_cosigned_blocks_hash() {
  let mut rng = new_test_rng();
  // Empty returns None
  {
    let db = MemDb::new();
    assert_eq!(Cosigning::<MemDb>::get_cosigned_blocks_hash(&db, rng.next_u64()).unwrap(), None);
  }

  // Returns None beyond latest finalized block
  {
    let mut db = MemDb::new();
    let latest_finalized_block = rng.next_u64().min(u64::MAX - 1);
    {
      let mut txn = db.txn();
      set_latest_cosigned_block_number(&mut txn, &latest_finalized_block);
      txn.commit();
    }
    assert_eq!(
      Cosigning::<MemDb>::get_cosigned_blocks_hash(&db, latest_finalized_block + 1).unwrap(),
      None
    );
  }

  // Returns hash when block is in range
  {
    let mut db = MemDb::new();
    let latest_finalized_block = rng.next_u64();
    let block_hash = random_block_hash(&mut rng);
    let block_number = rng.next_u64().min(latest_finalized_block);
    {
      let mut txn = db.txn();
      set_latest_cosigned_block_number(&mut txn, &latest_finalized_block);
      set_substrate_block_hash(&mut txn, block_number, &block_hash);
      txn.commit();
    }
    assert_eq!(
      Cosigning::<MemDb>::get_cosigned_blocks_hash(&db, block_number).unwrap(),
      Some(block_hash)
    );
  }

  // Panics when block is in range but hash is missing
  {
    let mut db = MemDb::new();
    let latest = 5u64;
    {
      let mut txn = db.txn();
      set_latest_cosigned_block_number(&mut txn, &latest);
      txn.commit();
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      Cosigning::<MemDb>::get_cosigned_blocks_hash(&db, 3).unwrap();
    }));

    let err = result.unwrap_err();
    let msg = err.downcast_ref::<String>().unwrap();
    assert!(msg.contains("cosigned the block 3 but didn't index it"), "wrong panic message: {msg}");
  }

  // Errors when faulted session exists
  {
    let mut db = MemDb::new();
    {
      let mut txn = db.txn();
      set_faulted_session(&mut txn, &random_global_cosigning_session_id(&mut rng));
      txn.commit();
    }
    assert!(matches!(
      Cosigning::<MemDb>::get_cosigned_blocks_hash(&db, rng.next_u64()),
      Err(Faulted)
    ));
  }
}

#[test]
fn all_networks_notable_or_latest_cosigns() {
  let mut rng = new_test_rng();
  // Empty without cosigns
  {
    let db = MemDb::new();
    let cosigns = Cosigning::<MemDb>::all_networks_notable_or_latest_cosigns(
      &db,
      random_global_cosigning_session_id(&mut rng),
    );
    assert!(cosigns.is_empty());
  }

  // Returns cosigns for session
  {
    let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
    // Ensure blocks are within the session range
    global_cosigning_session.start_block_number = 1;
    let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &global_cosigning_session);

    let block_number = rng.next_u64();
    let block_hash = random_block_hash(&mut rng);
    {
      let mut txn = db.txn();
      set_substrate_block_hash(&mut txn, block_number, &block_hash);
      txn.commit();
    }

    let mut expected_cosigns = vec![];
    for set in global_cosigning_session.cosigning_sets {
      let keypair = keypairs[&set.network].clone();
      let cosign =
        Cosign { global_cosigning_session: id, block_number, block_hash, cosigner: set.network };
      let signed = sign_cosign(cosign, &keypair);

      let mut cosigning = Cosigning::new(db.clone());
      cosigning.intake_cosign(&signed).unwrap();
      expected_cosigns.push(signed);
    }

    let all_networks_notable_or_latest_cosigns =
      Cosigning::<MemDb>::all_networks_notable_or_latest_cosigns(&db, id);

    for signed_cosign in &all_networks_notable_or_latest_cosigns {
      let Cosign {
        global_cosigning_session,
        block_number: cosign_block_number,
        block_hash: cosign_block_hash,
        cosigner,
      } = signed_cosign.cosign;
      assert_eq!(global_cosigning_session, id);
      assert_eq!(cosign_block_number, block_number);
      assert_eq!(cosign_block_hash, block_hash);
      assert!(
        expected_cosigns.iter().any(|ec| ec.cosign.cosigner == cosigner),
        "returned cosign has unexpected cosigner {cosigner:?}"
      );
    }
  }
}

/// For each network in `cosigning_sets`, intake a faulty cosign (under `session_id`)
/// and directly write a cosign (with `cosign_session_id` and `our_hash`)
/// under the `(session_id, network)` key.
///
/// The direct-write cosign's `global_cosigning_session` field is set to `cosign_session_id`,
/// which may differ from `session_id` to test exclusion of cross-session cosigns.
fn seed_faults_and_direct_cosigns(
  db: &mut MemDb,
  global_cosigning_session: &GlobalCosigningSession,
  keypairs: &HashMap<ExternalNetworkId, schnorrkel::Keypair>,
  block_number: u64,
  faulty_hash: BlockHash,
  cosign_session_id: GlobalCosigningSessionId,
  our_hash: BlockHash,
) {
  let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());
  for set in &global_cosigning_session.cosigning_sets {
    let keypair = keypairs[&set.network].clone();

    // Intake a faulty cosign for this network to record a fault
    let faulty_cosign = Cosign {
      global_cosigning_session: id,
      block_number,
      block_hash: faulty_hash,
      cosigner: set.network,
    };
    let faulty_signed = sign_cosign(faulty_cosign, &keypair);
    let mut cosigning = Cosigning::new(db.clone());
    cosigning.intake_cosign(&faulty_signed).unwrap();

    // Directly write a cosign under the session's key in NetworksLatestCosignedBlockIntaken
    let direct_cosign = Cosign {
      global_cosigning_session: cosign_session_id,
      block_number,
      block_hash: our_hash,
      cosigner: set.network,
    };
    let direct_signed = sign_cosign(direct_cosign, &keypair);
    let mut txn = db.txn();
    NetworksLatestCosignedBlockIntaken::set(&mut txn, id, set.network, &direct_signed);
    txn.commit();
  }
}

#[test]
fn cosigns_to_rebroadcast() {
  let mut rng = new_test_rng();
  // Returns both faults and honest cosigns when faulted session exists
  {
    let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
    // Ensure blocks are within the session range
    global_cosigning_session.start_block_number = 1;
    let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &global_cosigning_session);

    let block_number = rng.next_u64();
    let our_hash = random_block_hash(&mut rng);
    let faulty_hash = random_block_hash(&mut rng);
    {
      let mut txn = db.txn();
      set_substrate_block_hash(&mut txn, block_number, &our_hash);
      txn.commit();
    }

    seed_faults_and_direct_cosigns(
      &mut db,
      &global_cosigning_session,
      &keypairs,
      block_number,
      faulty_hash,
      // Both faults and honest cosigns share the same session ID
      id,
      our_hash,
    );

    let cosigning = Cosigning::new(db);
    let rebroadcast = cosigning.cosigns_to_rebroadcast();

    assert_eq!(rebroadcast.len(), global_cosigning_session.cosigning_sets.len() * 2);
    for signed in &rebroadcast {
      assert!(
        signed.cosign.block_hash == faulty_hash || signed.cosign.block_hash == our_hash,
        "unexpected block_hash in rebroadcast",
      );
    }
  }

  // Excludes cosigns from different global cosigning session
  {
    let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
    // Ensure blocks are within the session range
    global_cosigning_session.start_block_number = 1;
    let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &global_cosigning_session);

    let block_number = rng.next_u64();
    let our_hash = random_block_hash(&mut rng);
    let faulty_hash = random_block_hash(&mut rng);
    {
      let mut txn = db.txn();
      set_substrate_block_hash(&mut txn, block_number, &our_hash);
      txn.commit();
    }

    let different_session_id = random_global_cosigning_session_id(&mut rng);

    seed_faults_and_direct_cosigns(
      &mut db,
      &global_cosigning_session,
      &keypairs,
      block_number,
      faulty_hash,
      // Direct-write cosigns use a different session ID so they are filtered out
      different_session_id,
      our_hash,
    );

    let cosigning = Cosigning::new(db);
    let rebroadcast = cosigning.cosigns_to_rebroadcast();

    assert_eq!(rebroadcast.len(), global_cosigning_session.cosigning_sets.len());
    for signed in &rebroadcast {
      assert_eq!(signed.cosign.global_cosigning_session, id);
      assert_eq!(signed.cosign.block_hash, faulty_hash);
    }
  }

  // Returns latest cosigns when not faulted
  {
    let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
    // Ensure blocks are within the session range
    global_cosigning_session.start_block_number = 1;
    let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &global_cosigning_session);

    let block_number = rng.next_u64();
    let block_hash = random_block_hash(&mut rng);
    {
      let mut txn = db.txn();
      set_substrate_block_hash(&mut txn, block_number, &block_hash);
      txn.commit();
    }

    for set in &global_cosigning_session.cosigning_sets {
      let keypair = keypairs[&set.network].clone();
      let cosign =
        Cosign { global_cosigning_session: id, block_number, block_hash, cosigner: set.network };
      let signed = sign_cosign(cosign, &keypair);

      let mut cosigning = Cosigning::new(db.clone());
      cosigning.intake_cosign(&signed).unwrap();
    }

    let cosigning = Cosigning::new(db);
    let rebroadcast = cosigning.cosigns_to_rebroadcast();
    assert_eq!(rebroadcast.len(), global_cosigning_session.cosigning_sets.len());
    for signed in &rebroadcast {
      assert_eq!(signed.cosign.block_number, block_number);
      assert_eq!(signed.cosign.block_hash, block_hash);
    }
  }

  // Returns empty when empty
  {
    let db = MemDb::new();
    let cosigning = Cosigning::new(db);
    let rebroadcast = cosigning.cosigns_to_rebroadcast();
    assert_eq!(rebroadcast.len(), 0);
  }
}

mod intake_cosign {
  use super::*;

  mod errors {
    use super::*;

    #[test]
    fn rejects_not_yet_indexed_block() {
      let mut rng = new_test_rng();
      let db = MemDb::new();
      let (keypair, _) = random_schnorrkel_keypair(&mut rng);

      let signed = sign_cosign(random_cosign(&mut rng), &keypair);

      let mut cosigning = Cosigning::new(db);
      assert!(matches!(
        cosigning.intake_cosign(&signed),
        Err(IntakeCosignError::NotYetIndexedBlock)
      ));
    }

    #[test]
    fn rejects_stale_cosign() {
      let mut rng = new_test_rng();
      let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
      // Ensure all blocks are within the session range
      global_cosigning_session.start_block_number = 1;
      let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

      let mut db = MemDb::new();
      seed_minimal_state(&mut db, &global_cosigning_session);

      let base_block = rng.next_u64() / 2;
      // Ensure base_block >= start_block_number (1)
      let base_block = base_block.max(1);
      let block_hash_1 = random_block_hash(&mut rng);
      let block_hash_2 = random_block_hash(&mut rng);
      {
        let mut txn = db.txn();
        set_substrate_block_hash(&mut txn, base_block, &block_hash_1);
        set_substrate_block_hash(&mut txn, base_block + 1, &block_hash_2);
        txn.commit();
      }

      for set in &global_cosigning_session.cosigning_sets {
        let keypair = keypairs[&set.network].clone();

        // Intake a valid cosign for the newer block first
        let first_cosign = Cosign {
          global_cosigning_session: id,
          block_number: base_block + 1,
          block_hash: block_hash_2,
          cosigner: set.network,
        };
        let first_signed = sign_cosign(first_cosign, &keypair);

        let mut cosigning = Cosigning::new(db.clone());
        cosigning.intake_cosign(&first_signed).unwrap();

        // Now try to intake a stale cosign for the same network, older block
        let stale_cosign = Cosign {
          global_cosigning_session: id,
          block_number: base_block,
          block_hash: block_hash_1,
          cosigner: set.network,
        };
        let stale_signed = sign_cosign(stale_cosign, &keypair);

        assert!(matches!(
          cosigning.intake_cosign(&stale_signed),
          Err(IntakeCosignError::StaleCosign)
        ));
      }
    }

    #[test]
    fn rejects_unrecognized_global_cosigning_session() {
      let mut rng = new_test_rng();
      let (keypair, _) = random_schnorrkel_keypair(&mut rng);

      let mut db = MemDb::new();
      let block_number = rng.next_u64();
      let block_hash = random_block_hash(&mut rng);
      {
        let mut txn = db.txn();
        set_substrate_block_hash(&mut txn, block_number, &block_hash);
        txn.commit();
      }

      let cosign = Cosign {
        global_cosigning_session: random_global_cosigning_session_id(&mut rng),
        block_number,
        block_hash,
        cosigner: random_external_validator_set(&mut rng).network,
      };
      let signed = sign_cosign(cosign, &keypair);

      let mut cosigning = Cosigning::new(db);
      assert!(matches!(
        cosigning.intake_cosign(&signed),
        Err(IntakeCosignError::UnrecognizedGlobalSession)
      ));
    }

    #[test]
    fn rejects_before_global_cosigning_session_start() {
      let mut rng = new_test_rng();
      let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
      global_cosigning_session.start_block_number = rng.next_u64();
      let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

      let block_hash = random_block_hash(&mut rng);
      let mut db = MemDb::new();
      {
        let mut txn = db.txn();
        GlobalCosigningSessions::set(&mut txn, id, &global_cosigning_session);
        evaluator::CurrentGlobalCosigningSessionEvaluator::set(
          &mut txn,
          &(id, global_cosigning_session.clone()),
        );
        set_latest_cosigned_block_number(&mut txn, &global_cosigning_session.start_block_number);
        set_substrate_block_hash(
          &mut txn,
          global_cosigning_session.start_block_number - 1,
          &block_hash,
        );
        txn.commit();
      }

      for set in &global_cosigning_session.cosigning_sets {
        let keypair = keypairs[&set.network].clone();

        let cosign = Cosign {
          global_cosigning_session: id,
          block_number: global_cosigning_session.start_block_number - 1,
          block_hash,
          cosigner: set.network,
        };
        let signed = sign_cosign(cosign, &keypair);

        let mut cosigning = Cosigning::new(db.clone());
        assert!(matches!(
          cosigning.intake_cosign(&signed),
          Err(IntakeCosignError::BeforeGlobalSessionStart)
        ));
      }
    }

    #[test]
    fn rejects_after_global_cosigning_session_end() {
      let mut rng = new_test_rng();
      let (global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
      let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

      let mut db = MemDb::new();
      seed_minimal_state(&mut db, &global_cosigning_session);

      let block_hash = random_block_hash(&mut rng);
      let block_number = rng.next_u64();
      // Ensure block_number > start_block_number so it passes BeforeGlobalSessionStart
      let block_number = block_number.max(global_cosigning_session.start_block_number + 1);
      {
        let mut txn = db.txn();
        GlobalCosigningSessionsLastBlock::set(&mut txn, id, &(block_number - 1));
        set_substrate_block_hash(&mut txn, block_number, &block_hash);
        txn.commit();
      }

      for set in &global_cosigning_session.cosigning_sets {
        let keypair = keypairs[&set.network].clone();

        let cosign =
          Cosign { global_cosigning_session: id, block_number, block_hash, cosigner: set.network };
        let signed = sign_cosign(cosign, &keypair);

        let mut cosigning = Cosigning::new(db.clone());
        assert!(matches!(
          cosigning.intake_cosign(&signed),
          Err(IntakeCosignError::AfterGlobalSessionEnd)
        ));
      }
    }

    #[test]
    fn rejects_invalid_signature() {
      let mut rng = new_test_rng();
      let (mut global_cosigning_session, _keypairs) = random_global_cosigning_session(&mut rng);
      // Ensure blocks are within the session range so we get past BeforeGlobalSessionStart
      global_cosigning_session.start_block_number = 1;
      let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

      let mut db = MemDb::new();
      seed_minimal_state(&mut db, &global_cosigning_session);

      let block_number = rng.next_u64();
      let block_hash = random_block_hash(&mut rng);
      {
        let mut txn = db.txn();
        set_substrate_block_hash(&mut txn, block_number, &block_hash);
        txn.commit();
      }

      for set in &global_cosigning_session.cosigning_sets {
        // Generate a wrong keypair (not matching the session's key for this network)
        let (wrong_keypair, _) = random_schnorrkel_keypair(&mut rng);

        let cosign =
          Cosign { global_cosigning_session: id, block_number, block_hash, cosigner: set.network };
        let signed = sign_cosign(cosign, &wrong_keypair);

        let mut cosigning = Cosigning::new(db.clone());
        assert!(matches!(
          cosigning.intake_cosign(&signed),
          Err(IntakeCosignError::InvalidSignature)
        ));
      }
    }

    #[test]
    fn rejects_future_global_cosigning_session() {
      let mut rng = new_test_rng();
      let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
      global_cosigning_session.start_block_number = rng.next_u64();
      let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

      let block_hash = random_block_hash(&mut rng);
      let mut db = MemDb::new();
      {
        let mut txn = db.txn();
        GlobalCosigningSessions::set(&mut txn, id, &global_cosigning_session);
        evaluator::CurrentGlobalCosigningSessionEvaluator::set(
          &mut txn,
          &(id, global_cosigning_session.clone()),
        );
        set_latest_cosigned_block_number(
          &mut txn,
          &(global_cosigning_session.start_block_number - 2),
        );
        set_substrate_block_hash(
          &mut txn,
          global_cosigning_session.start_block_number,
          &block_hash,
        );
        txn.commit();
      }

      for set in &global_cosigning_session.cosigning_sets {
        let keypair = keypairs[&set.network].clone();

        let cosign = Cosign {
          global_cosigning_session: id,
          block_number: global_cosigning_session.start_block_number,
          block_hash,
          cosigner: set.network,
        };
        let signed = sign_cosign(cosign, &keypair);

        let mut cosigning = Cosigning::new(db.clone());
        assert!(matches!(
          cosigning.intake_cosign(&signed),
          Err(IntakeCosignError::FutureGlobalSession)
        ));
      }
    }

    #[test]
    fn rejects_non_participating_network() {
      let mut rng = new_test_rng();
      // Build a session with a single set to guarantee a non-participating network exists.
      let session_network = random_external_network_id(&mut rng);
      let set = ExternalValidatorSet { network: session_network, session: Session(rng.next_u32()) };
      let (_keypair, public) = random_schnorrkel_keypair(&mut rng);
      let stake = rng.gen_range(1u64 .. u64::MAX / 17);
      let session = GlobalCosigningSession {
        start_block_number: u64::from(set.session.0) + 1,
        cosigning_sets: vec![set],
        keys: HashMap::from([(session_network, public)]),
        stakes: HashMap::from([(session_network, stake)]),
        total_stake: stake,
      };
      let id = GlobalCosigningSession::id(session.cosigning_sets.clone());

      let non_participating_network =
        ExternalNetworkId::all().find(|n| *n != session_network).unwrap();
      let (other_keypair, _) = random_schnorrkel_keypair(&mut rng);

      let mut db = MemDb::new();
      seed_minimal_state(&mut db, &session);

      let block_number = rng.next_u64();
      let block_hash = random_block_hash(&mut rng);
      {
        let mut txn = db.txn();
        set_substrate_block_hash(&mut txn, block_number, &block_hash);
        txn.commit();
      }

      let cosign = Cosign {
        global_cosigning_session: id,
        block_number,
        block_hash,
        cosigner: non_participating_network,
      };
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
    let mut rng = new_test_rng();
    let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
    // Ensure block_number >= start_block_number for all networks
    global_cosigning_session.start_block_number = 1;
    let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &global_cosigning_session);

    let block_number = rng.next_u64();
    let block_hash = random_block_hash(&mut rng);
    {
      let mut txn = db.txn();
      set_substrate_block_hash(&mut txn, block_number, &block_hash);
      txn.commit();
    }

    for set in &global_cosigning_session.cosigning_sets {
      let keypair = keypairs[&set.network].clone();
      let cosign =
        Cosign { global_cosigning_session: id, block_number, block_hash, cosigner: set.network };
      let signed = sign_cosign(cosign, &keypair);

      let mut cosigning = Cosigning::new(db.clone());
      cosigning.intake_cosign(&signed).unwrap();
    }
  }

  #[test]
  fn handles_faulty_cosign() {
    let mut rng = new_test_rng();
    let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
    // Ensure blocks are within the session range
    global_cosigning_session.start_block_number = 1;
    let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &global_cosigning_session);

    let block_number = rng.next_u64();
    let our_hash = random_block_hash(&mut rng);
    let faulty_hash = random_block_hash(&mut rng);
    {
      let mut txn = db.txn();
      set_substrate_block_hash(&mut txn, block_number, &our_hash);
      txn.commit();
    }

    for set in &global_cosigning_session.cosigning_sets {
      let keypair = keypairs[&set.network].clone();
      let cosign = Cosign {
        global_cosigning_session: id,
        block_number,
        block_hash: faulty_hash,
        cosigner: set.network,
      };
      let signed = sign_cosign(cosign, &keypair);

      let mut cosigning = Cosigning::new(db.clone());
      cosigning.intake_cosign(&signed).unwrap();
    }

    // All networks should have their faults recorded
    let faults: Option<Vec<SignedCosign>> = Faults::get(&db, id);
    assert!(faults.is_some());
    let faults = faults.unwrap();
    assert_eq!(faults.len(), global_cosigning_session.cosigning_sets.len());
    for fault in &faults {
      assert_eq!(fault.cosign.block_hash, faulty_hash);
      assert!(global_cosigning_session
        .cosigning_sets
        .iter()
        .any(|set| set.network == fault.cosign.cosigner));
    }

    // Session should be marked as faulted
    let faulted: Option<[u8; 32]> = FaultedCosigningSession::get(&db);
    assert_eq!(faulted, Some(id));
  }

  #[test]
  fn accepts_newer_cosign_when_existing_is_older() {
    let mut rng = new_test_rng();
    let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
    // Ensure all blocks are within the session range
    global_cosigning_session.start_block_number = 1;
    let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &global_cosigning_session);

    let block_number1 = rng.next_u64();
    let block_hash_1 = random_block_hash(&mut rng);
    let block_number2 = block_number1 + 1;
    let block_hash_2 = random_block_hash(&mut rng);
    {
      let mut txn = db.txn();
      set_substrate_block_hash(&mut txn, block_number1, &block_hash_1);
      set_substrate_block_hash(&mut txn, block_number2, &block_hash_2);
      txn.commit();
    }

    for set in &global_cosigning_session.cosigning_sets {
      let keypair = keypairs[&set.network].clone();

      let first_cosign = Cosign {
        global_cosigning_session: id,
        block_number: block_number1,
        block_hash: block_hash_1,
        cosigner: set.network,
      };
      let first_signed = sign_cosign(first_cosign, &keypair);

      let mut cosigning = Cosigning::new(db.clone());
      cosigning.intake_cosign(&first_signed).unwrap();

      let newer_cosign = Cosign {
        global_cosigning_session: id,
        block_number: block_number2,
        block_hash: block_hash_2,
        cosigner: set.network,
      };
      let newer_signed = sign_cosign(newer_cosign, &keypair);

      cosigning.intake_cosign(&newer_signed).unwrap();

      // The latest for THIS network should be the newer block
      let latest = NetworksLatestCosignedBlockIntaken::get(&db, id, set.network).unwrap();
      assert_eq!(latest.cosign.block_number, block_number2);
    }

    // Verify cosigns_to_rebroadcast returns the newer cosign for all networks
    let cosigning = Cosigning::new(db);
    let rebroadcast = cosigning.cosigns_to_rebroadcast();
    assert_eq!(rebroadcast.len(), global_cosigning_session.cosigning_sets.len());
    for signed in &rebroadcast {
      assert_eq!(signed.cosign.block_number, block_number2);
      assert_eq!(signed.cosign.block_hash, block_hash_2);
    }
  }

  #[test]
  fn accepts_cosign_at_global_cosigning_session_last_block() {
    let mut rng = new_test_rng();
    let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
    let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

    // Set a small start_block_number (1) so the test loop that populates block hashes up to
    // last_block doesn't iterate billions of times, while still >= 1 so
    // set_latest_cosigned_block_number(start_block_number - 1) = 0 doesn't underflow
    global_cosigning_session.start_block_number = 1;

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &global_cosigning_session);

    let last_block = u64::from(rng.next_u32() % 100) + 1; // any from 1 to 100
    let mut block_hashes = Vec::new();
    {
      let mut txn = db.txn();
      GlobalCosigningSessionsLastBlock::set(&mut txn, id, &last_block);
      for i in 0 ..= last_block {
        let hash = random_block_hash(&mut rng);
        set_substrate_block_hash(&mut txn, i, &hash);
        block_hashes.push(hash);
      }
      txn.commit();
    }

    for set in &global_cosigning_session.cosigning_sets {
      let keypair = keypairs[&set.network].clone();

      let mut cosigning = Cosigning::new(db.clone());

      let cosign = Cosign {
        global_cosigning_session: id,
        block_number: last_block,
        block_hash: block_hashes[usize::try_from(last_block).unwrap()],
        cosigner: set.network,
      };
      let signed = sign_cosign(cosign, &keypair);

      cosigning.intake_cosign(&signed).unwrap();

      let latest = NetworksLatestCosignedBlockIntaken::get(&db, id, set.network).unwrap();
      assert_eq!(latest.cosign.block_number, last_block);
    }
  }

  #[test]
  fn ignores_duplicate_fault_from_same_network() {
    let mut rng = new_test_rng();
    let (mut global_cosigning_session, keypairs) = random_global_cosigning_session(&mut rng);
    // Ensure blocks are within the session range
    global_cosigning_session.start_block_number = 1;
    let id = GlobalCosigningSession::id(global_cosigning_session.cosigning_sets.clone());

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &global_cosigning_session);

    let block_number = rng.next_u64();
    let our_hash = random_block_hash(&mut rng);
    let faulty_hash_1 = random_block_hash(&mut rng);
    let faulty_hash_2 = random_block_hash(&mut rng);
    {
      let mut txn = db.txn();
      set_substrate_block_hash(&mut txn, block_number, &our_hash);
      txn.commit();
    }

    for set in &global_cosigning_session.cosigning_sets {
      let keypair = keypairs[&set.network].clone();

      let faulty_cosign_1 = Cosign {
        global_cosigning_session: id,
        block_number,
        block_hash: faulty_hash_1,
        cosigner: set.network,
      };
      let faulty_signed_1 = sign_cosign(faulty_cosign_1, &keypair);

      let mut cosigning = Cosigning::new(db.clone());
      cosigning.intake_cosign(&faulty_signed_1).unwrap();

      // Second faulty cosign from the same network should be ignored
      let faulty_cosign_2 = Cosign {
        global_cosigning_session: id,
        block_number,
        block_hash: faulty_hash_2,
        cosigner: set.network,
      };
      let faulty_signed_2 = sign_cosign(faulty_cosign_2, &keypair);

      cosigning.intake_cosign(&faulty_signed_2).unwrap();

      // Verify only the first fault is kept
      let faults_after_second = Faults::get(&db, id).unwrap();
      assert_eq!(
        faults_after_second.iter().filter(|f| f.cosign.cosigner == set.network).count(),
        1,
        "duplicate fault from same network should not be added"
      );
      let our_fault =
        faults_after_second.iter().find(|f| f.cosign.cosigner == set.network).unwrap();
      assert_eq!(our_fault.cosign.block_hash, faulty_hash_1);
    }
  }

  #[test]
  fn records_fault_below_threshold() {
    let mut rng = new_test_rng();
    let set1 = random_external_validator_set(&mut rng);
    let network1 = set1.network;
    // Ensure we pick a distinct second network
    let network2 = ExternalNetworkId::all().find(|n| *n != network1).unwrap();
    let set2 = ExternalValidatorSet { network: network2, session: Session(rng.next_u32()) };

    let (keypair1, public1) = random_schnorrkel_keypair(&mut rng);
    let (_, public2) = random_schnorrkel_keypair(&mut rng);

    let mut keys = HashMap::new();
    let mut stakes = HashMap::new();

    keys.insert(network1, public1);
    keys.insert(network2, public2);

    // stake1 must be below the 17% threshold: stake1 < (total_stake * 17) / 100
    let total_stake = rng.gen_range(100u64 .. 10_000);
    let max_below_threshold = (total_stake * 17) / 100;
    let stake1 = rng.gen_range(1 .. max_below_threshold.max(2));
    let stake2 = total_stake - stake1;

    stakes.insert(network1, stake1);
    stakes.insert(network2, stake2);

    let session = GlobalCosigningSession {
      start_block_number: u64::from(set1.session.0) + 1,
      cosigning_sets: vec![set1, set2],
      keys,
      stakes,
      total_stake,
    };
    let id = GlobalCosigningSession::id(session.cosigning_sets.clone());

    let mut db = MemDb::new();
    seed_minimal_state(&mut db, &session);

    let block_number = rng.next_u64();
    let our_hash = random_block_hash(&mut rng);
    let faulty_hash = random_block_hash(&mut rng);
    {
      let mut txn = db.txn();
      set_substrate_block_hash(&mut txn, block_number, &our_hash);
      txn.commit();
    }

    let faulty_cosign = Cosign {
      global_cosigning_session: id,
      block_number,
      block_hash: faulty_hash,
      cosigner: network1,
    };
    let faulty_signed = sign_cosign(faulty_cosign, &keypair1);

    let mut cosigning = Cosigning::new(db.clone());
    cosigning.intake_cosign(&faulty_signed).unwrap();

    let faults = Faults::get(&db, id).unwrap();
    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].cosign.block_hash, faulty_hash);

    let faulted = FaultedCosigningSession::get(&db);
    assert_eq!(faulted, None, "session should not be faulted when weight is below 17% threshold");
  }
}

#[test]
fn all_intended_cosigns_for_network() {
  let mut rng = new_test_rng();
  // Empty returns empty
  {
    let mut db = MemDb::new();
    let set = random_external_validator_set(&mut rng);
    let mut txn = db.txn();
    assert!(Cosigning::<MemDb>::all_intended_cosigns_for_network(&mut txn, set).is_empty());
    txn.commit();
  }

  // Receives sent intent
  {
    let mut db = MemDb::new();
    let set = random_external_validator_set(&mut rng);
    let intent = random_cosign_intent(&mut rng);

    {
      let mut txn = db.txn();
      intend::NetworksIntendedCosigns::send(&mut txn, set, &intent);
      txn.commit();
    }

    {
      let mut txn = db.txn();
      let got = Cosigning::<MemDb>::all_intended_cosigns_for_network(&mut txn, set);
      txn.commit();
      assert_eq!(got.len(), 1);
      let CosignIntent { global_cosigning_session, block_number, block_hash, notable } = got[0];
      assert_eq!(global_cosigning_session, intent.global_cosigning_session);
      assert_eq!(block_number, intent.block_number);
      assert_eq!(block_hash, intent.block_hash);
      assert_eq!(notable, intent.notable);
    }
  }

  // Sends and retrieves intents for random sets with random intent counts
  {
    let mut db = MemDb::new();

    let num_sets = rng.gen_range(1 ..= 5);
    let mut expected_intents: Vec<(ExternalValidatorSet, Vec<CosignIntent>)> = vec![];

    for _ in 0 .. num_sets {
      let set = random_external_validator_set(&mut rng);
      let num_intents = rng.gen_range(1 ..= 10);
      let mut intents = Vec::with_capacity(num_intents);
      for i in 0 .. num_intents {
        let mut intent = random_cosign_intent(&mut rng);
        // Ensure the last intent is notable so the function drains the full batch
        intent.notable = i == num_intents - 1;
        intents.push(intent);
      }

      let mut txn = db.txn();
      for intent in &intents {
        intend::NetworksIntendedCosigns::send(&mut txn, set, intent);
      }
      txn.commit();

      expected_intents.push((set, intents));
    }

    for (set, expected) in &expected_intents {
      let mut txn = db.txn();
      let got = Cosigning::<MemDb>::all_intended_cosigns_for_network(&mut txn, *set);
      txn.commit();

      assert_eq!(got.len(), expected.len(), "wrong intent count for set {set:?}");
      for (got_intent, exp_intent) in got.iter().zip(expected.iter()) {
        assert_eq!(got_intent, exp_intent);
      }
    }

    // Verify all queues are drained after reading
    for (set, _) in &expected_intents {
      let mut txn = db.txn();
      let got = Cosigning::<MemDb>::all_intended_cosigns_for_network(&mut txn, *set);
      txn.commit();
      assert!(got.is_empty(), "queue should be drained after reading all intents for {set:?}");
    }
  }
}
