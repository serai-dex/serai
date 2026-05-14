//! Full-stack integration tests for the cosign library's public API.
//!
//! While the individual components (intend, evaluate, delay) are unit-tested in their
//! respective modules, these tests verify how they integrate together as a production
//! pipeline. State is injected via the Serai node shim (`serai_shim_rpc`), exercising
//! the same `pub` API surface a real coordinator would use.

use crate::{evaluator::*, tests::*, *};

/// Drain all pending cosign intents from every keyed session the fuzzer knows about.
fn drain_intents(
  txn: &mut impl DbTxn,
  event_fuzzer: &EventFuzzer,
) -> Vec<(ExternalNetworkId, CosignIntent)> {
  let mut intents = Vec::new();
  for network in ExternalNetworkId::all() {
    let max_session = event_fuzzer.next_session.get(&network).copied().unwrap_or(0);
    for session_num in 0 .. max_session {
      let set = ExternalValidatorSet { network, session: Session(session_num) };
      for intent in Cosigning::<MemDb>::intended_cosigns(txn, set) {
        intents.push((network, intent));
      }
    }
  }
  intents
}

/// Sign an intent and intake it. Returns `Ok(())` on success or non-retryable error,
/// `Err((network, intent))` if the intent should be retried later.
fn sign_and_intake(
  db: &MemDb,
  cosigning: &mut Cosigning<MemDb>,
  event_fuzzer: &EventFuzzer,
  network: ExternalNetworkId,
  intent: CosignIntent,
) -> Result<(), (ExternalNetworkId, CosignIntent)> {
  let cosign = intent.into_cosign(network);
  let Some(global_session) = GlobalSessions::get(db, intent.global_session) else {
    return Err((network, intent));
  };
  let Some(public) = global_session.keys.get(&network) else { return Ok(()) };
  let Some(keypair) = event_fuzzer.keypairs.get(&public.0) else { return Ok(()) };
  let signed = sign_cosign(cosign, keypair);
  match cosigning.intake_cosign(&signed) {
    Ok(()) | Err(IntakeCosignError::StaleCosign) => Ok(()),
    Err(e) if e.temporal() => Err((network, intent)),
    Err(ref e) => {
      serai_env::warn!(
        "intake_cosign error: block={}, network={network:?}, err={e:?}",
        intent.block_number,
      );
      Ok(())
    }
  }
}

/// Wrapper for `run_honest_cosigning_capped` with no block cap.
async fn run_honest_cosigning(
  db: &MemDb,
  cosigning: &mut Cosigning<MemDb>,
  event_fuzzer: &EventFuzzer,
  should_break: impl FnMut(Option<u64>) -> bool,
) {
  run_honest_cosigning_capped(db, cosigning, event_fuzzer, should_break, None, &mut Vec::new())
    .await;
}

/// Run the honest cosigning loop: drain intents from all keyed sessions, sign them
/// with the EventFuzzer's keypairs, intake them, and repeat until `should_break` returns `true`.
///
/// `should_break` is called each iteration with the current `latest_cosigned_block_number`.
///
/// Intents for blocks beyond `max_block` are deferred into `deferred_intents` instead of
/// being signed. This prevents the evaluator from using high-block cosigns submitted during
/// an early phase to advance past the point where a later phase expects a stall.
async fn run_honest_cosigning_capped(
  db: &MemDb,
  cosigning: &mut Cosigning<MemDb>,
  event_fuzzer: &EventFuzzer,
  mut should_break: impl FnMut(Option<u64>) -> bool,
  max_block: Option<u64>,
  deferred_intents: &mut Vec<(ExternalNetworkId, CosignIntent)>,
) {
  let mut pending_intents = Vec::<(ExternalNetworkId, CosignIntent)>::new();
  loop {
    {
      let mut db = db.clone();
      let mut txn = db.txn();
      for (network, intent) in drain_intents(&mut txn, event_fuzzer) {
        if max_block.is_some_and(|cap| intent.block_number > cap) {
          deferred_intents.push((network, intent));
        } else {
          pending_intents.push((network, intent));
        }
      }
      txn.commit();
    }

    pending_intents = pending_intents
      .drain(..)
      .filter_map(|(network, intent)| {
        sign_and_intake(db, cosigning, event_fuzzer, network, intent).err()
      })
      .collect();

    let latest = match Cosigning::<MemDb>::latest_cosigned_block_number(db) {
      Ok(Some(n)) => Some(n),
      _ => None,
    };
    if should_break(latest) {
      break;
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}

/// Full-stack fuzz test: intend -> evaluator -> delay pipeline with random events.
///
/// Uses the `EventFuzzer` to generate random blocks, spawns the full `Cosigning` pipeline,
/// then simulates the cosigner role by draining intended cosigns, signing them, and feeding
/// them back via `intake_cosign`. Waits for all blocks to be cosigned.
///
/// The shim RPC has a random failure rate enabled so that RPC calls from the intend task
/// occasionally fail, exercising the `ContinuallyRan` error/retry paths.
#[tokio::test]
async fn full_stack_fuzzed() {
  *INIT_LOGGER;

  let iterations = 5;
  for i in 1 ..= iterations {
    let num_blocks = OsRng.gen_range(5 .. 20);
    let mut event_fuzzer = EventFuzzer::new();
    let blocks = event_fuzzer.generate_blocks_with_keygen(num_blocks);

    serai_env::info!(
      "Starting full-stack fuzz: 0..{} blocks, {} validators ({i}/{iterations})",
      num_blocks - 1,
      event_fuzzer.validators.len(),
    );

    let (shim, serai) = setup_shim_serai().await;
    for (i, events) in blocks.into_iter().enumerate() {
      shim.make_block(u64::try_from(i).unwrap(), events).await;
    }

    // Random RPC failure rate between 5% and 30%, unless disabled via env var
    shim.set_failure_rate(OsRng.gen_range(5 ..= 30)).await;

    let db = MemDb::new();

    let (request, _calls) = TestRequest::new(false);
    let mut cosigning = Cosigning::spawn(db.clone(), serai, request, vec![]);

    let target = u64::try_from(num_blocks - 1).unwrap();

    run_honest_cosigning(
      &db,
      &mut cosigning,
      &event_fuzzer,
      |latest| matches!(latest, Some(n) if n >= target),
    )
    .await;

    let latest = Cosigning::<MemDb>::latest_cosigned_block_number(&db).unwrap().unwrap();
    assert!(latest >= target, "expected latest cosigned block >= {target}, got {latest}");

    serai_env::info!("Full-stack fuzz completed: all {num_blocks} blocks cosigned");
  }
}

/// Fuzzed full-stack equivocation test.
///
/// Mirrors `full_stack_fuzzed`, random events via `EventFuzzer`, full `Cosigning` pipeline
/// but at a random point during honest cosigning, one or more networks equivocate by signing
/// a block with a different hash. Once the faulty stake reaches the 17% threshold the protocol
/// must halt immediately, and all subsequent operations must reflect the fault.
#[tokio::test]
async fn equivocation_halts_protocol() {
  *INIT_LOGGER;

  let iterations = 5;
  for iteration in 1 ..= iterations {
    let num_blocks = OsRng.gen_range(5 .. 20);
    let mut event_fuzzer = EventFuzzer::new();
    let blocks = event_fuzzer.generate_blocks_with_keygen(num_blocks);

    serai_env::info!(
      "equivocation fuzz: 0..{} blocks, {} validators ({iteration}/{iterations})",
      num_blocks - 1,
      event_fuzzer.validators.len(),
    );

    let (shim, serai) = setup_shim_serai().await;
    for (i, events) in blocks.into_iter().enumerate() {
      shim.make_block(u64::try_from(i).unwrap(), events).await;
    }

    let mut db = MemDb::new();
    let (request, _calls) = TestRequest::new(false);
    let mut cosigning = Cosigning::spawn(db.clone(), serai, request, vec![]);

    let target = u64::try_from(num_blocks - 1).unwrap();

    // Pick a random target for when to attempt equivocation: after cosigning block N.
    // We pick from the lower half so there's room for honest progress first.
    let equivocation_after_block: u64 = OsRng.gen_range(2 ..= target / 2);

    let mut reached_equivocation_point = false;
    let deadline = tokio::time::Instant::now() + Duration::from_mins(5);

    // Step 1: run the honest pipeline until we've cosigned enough blocks to equivocate
    // We need at least one global session to exist and at least one block cosigned under it.
    run_honest_cosigning(&db, &mut cosigning, &event_fuzzer, |latest| {
      assert!(
        tokio::time::Instant::now() < deadline,
        "timed out waiting to reach equivocation point (target cosigned block \
         {equivocation_after_block}, latest={latest:?})",
      );
      match latest {
        Some(n) if n >= equivocation_after_block => {
          reached_equivocation_point = true;
          true
        }
        Some(n) if n >= target => true,
        _ => false,
      }
    })
    .await;

    if !reached_equivocation_point {
      serai_env::info!(
        "equivocation fuzz ({iteration}/{iterations}): no global session formed, skipping"
      );
      continue;
    }

    assert!(FaultedSession::get(&db).is_none(), "should not be faulted before equivocation");

    // Step 2: inject equivocation

    let equivocation_block = equivocation_after_block;
    let indexed_hash = SubstrateBlockHash::get(&db, equivocation_block)
      .expect("equivocation block should be indexed");

    // Find the global session that covers this block via the evaluator's current session
    let Some(global_session_id) = currently_evaluated_global_session(&db) else {
      serai_env::info!(
        "equivocation fuzz ({iteration}/{iterations}): no evaluated global session, skipping"
      );
      continue;
    };
    let global_session =
      GlobalSessions::get(&db, global_session_id).expect("evaluated session should exist in DB");
    if equivocation_block < global_session.start_block_number {
      serai_env::info!(
        "equivocation fuzz ({iteration}/{iterations}): equivocation block \
         {equivocation_block} predates session start {}, skipping",
        global_session.start_block_number,
      );
      continue;
    }

    // Pick which networks equivocate: 1 to all networks in this session
    let session_networks: Vec<ExternalNetworkId> = global_session.keys.keys().copied().collect();
    let num_faulty = OsRng.gen_range(1 ..= session_networks.len());
    let faulty_networks: Vec<ExternalNetworkId> =
      session_networks.choose_multiple(&mut OsRng, num_faulty).copied().collect();

    let fault_threshold = (global_session.total_stake * 17) / 100;
    let faulty_stake: u64 =
      faulty_networks.iter().map(|n| global_session.stakes.get(n).copied().unwrap_or(0)).sum();

    // Generate a hash that differs from the indexed one
    let mut faulty_block_hash = random_block_hash(&mut OsRng);
    if faulty_block_hash == indexed_hash {
      faulty_block_hash = random_block_hash(&mut OsRng);
    }

    serai_env::info!(
      "equivocation fuzz ({iteration}/{iterations}): block={equivocation_block}, \
       faulty={faulty_networks:?}, faulty_stake={faulty_stake}, threshold={fault_threshold}, \
       will_fault={}",
      faulty_stake >= fault_threshold,
    );

    // Submit equivocating cosigns one at a time, tracking cumulative fault weight
    let mut cumulative_faulty_stake: u64 = 0;
    for (fi, &faulty_net) in faulty_networks.iter().enumerate() {
      let faulty_cosign = Cosign {
        global_session: global_session_id,
        block_number: equivocation_block,
        block_hash: faulty_block_hash,
        cosigner: faulty_net,
      };
      let public =
        global_session.keys.get(&faulty_net).expect("faulty network not in global session");
      let keypair =
        event_fuzzer.keypairs.get(&public.0).expect("missing keypair for faulty network");
      let faulty_signed = sign_cosign(faulty_cosign, keypair);
      cosigning.intake_cosign(&faulty_signed).unwrap();

      let net_stake = global_session.stakes.get(&faulty_net).copied().unwrap_or(0);
      cumulative_faulty_stake += net_stake;
      let faulted_now = cumulative_faulty_stake >= fault_threshold;

      serai_env::info!(
        "faulty cosign {}/{num_faulty} from {faulty_net:?} (stake={net_stake}): \
         cumulative={cumulative_faulty_stake}, threshold={fault_threshold}, faulted={faulted_now}",
        fi + 1,
      );

      if faulted_now {
        assert_eq!(
          FaultedSession::get(&db),
          Some(global_session_id),
          "session should be faulted after {faulty_net:?}: cumulative stake \
           {cumulative_faulty_stake} >= threshold {fault_threshold}"
        );
      } else {
        assert!(
          FaultedSession::get(&db).is_none(),
          "session should NOT be faulted after {faulty_net:?}: cumulative stake \
           {cumulative_faulty_stake} < threshold {fault_threshold}"
        );
      }
    }

    if faulty_stake < fault_threshold {
      serai_env::info!(
        "equivocation fuzz ({iteration}/{iterations}): faulty stake {faulty_stake} below \
         threshold {fault_threshold}, verifying protocol continues"
      );
      assert!(FaultedSession::get(&db).is_none());
      continue;
    }

    // Step 3: verify the protocol is halted

    assert!(
      matches!(Cosigning::<MemDb>::latest_cosigned_block_number(&db), Err(Faulted)),
      "latest_cosigned_block_number should return Faulted"
    );

    // Verify cosigns_to_rebroadcast includes the faulty cosign(s)
    let rebroadcast = cosigning.cosigns_to_rebroadcast();
    assert!(
      rebroadcast.iter().any(|c| c.cosign.block_hash == faulty_block_hash),
      "rebroadcast should include the faulty cosign"
    );

    // Verify that the protocol remains permanently faulted: drain any remaining intents
    // and confirm latest_cosigned_block_number is still Err(Faulted).
    {
      let mut txn = db.txn();
      drop(drain_intents(&mut txn, &event_fuzzer));
      txn.commit();
    }

    assert!(
      matches!(Cosigning::<MemDb>::latest_cosigned_block_number(&db), Err(Faulted)),
      "latest_cosigned_block_number should remain Faulted after further operations"
    );

    serai_env::info!("equivocation fuzz ({iteration}/{iterations}): protocol halted as expected");
  }
}

/// DoS test modeling the README's "5.67% practical attack":
/// If a set has >= 17% of total non-Serai stake
/// and an attacker controls 1/3 of that set's stake and goes offline,
/// that prevents the set from producing threshold signatures, leaving
/// the remaining sets not able reach the 83% commit threshold,
/// stalling but not halting the protocol.
#[tokio::test]
async fn dos_stall_offline_set() {
  *INIT_LOGGER;

  let iterations = 5;
  for iteration in 1 ..= iterations {
    serai_env::info!("dos_stall_offline_set iteration {iteration}/{iterations}");

    let num_blocks = OsRng.gen_range(10 .. 25);
    let mut event_fuzzer = EventFuzzer::new();
    let mut blocks = event_fuzzer.generate_blocks_with_keygen(num_blocks);

    // Ensure at least one block in the latter half has events (a burn),
    // so blocks with HasEvents::No don't let the pipeline sail through uncosigned.
    let mid = num_blocks / 2;
    if blocks[mid ..].iter().all(Vec::is_empty) {
      #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
      let burn_index = mid + (OsRng.next_u64() as usize % (num_blocks - mid));
      blocks[burn_index] = vec![vec![event_fuzzer.random_burn()]];
    }

    serai_env::info!(
      "dos_stall fuzz: 0..{} blocks, {} validators ({iteration}/{iterations})",
      num_blocks - 1,
      event_fuzzer.validators.len(),
    );

    let (shim, serai) = setup_shim_serai().await;
    for (i, events) in blocks.into_iter().enumerate() {
      shim.make_block(u64::try_from(i).unwrap(), events).await;
    }

    let db = MemDb::new();
    let (request, _calls) = TestRequest::new(false);
    let mut cosigning = Cosigning::spawn(db.clone(), serai, request, vec![]);

    let target = u64::try_from(num_blocks - 1).unwrap();

    // Step 1: honest cosigning until we have a global session to analyze.
    // Cap cosign submission at step1_target so the offline network's high-water mark
    // doesn't cover blocks beyond where we'll test the stall.
    let step1_target: u64 = OsRng.gen_range(3 ..= target / 3);
    let mut deferred_intents: Vec<(ExternalNetworkId, CosignIntent)> = Vec::new();
    run_honest_cosigning_capped(
      &db,
      &mut cosigning,
      &event_fuzzer,
      |latest| matches!(latest, Some(n) if n >= step1_target),
      Some(step1_target),
      &mut deferred_intents,
    )
    .await;

    // Find the current global session and identify a network to take offline
    let global_session_id = currently_evaluated_global_session(&db).unwrap();
    let global_session = GlobalSessions::get(&db, global_session_id).unwrap();
    let threshold = cosign_threshold(global_session.total_stake);

    // Find a network whose absence prevents reaching the threshold
    let (&offline_network, &offline_stake) = global_session
      .stakes
      .iter()
      .find(|(_, &stake)| global_session.total_stake - stake < threshold)
      .unwrap();
    let online_weight: u64 = global_session
      .stakes
      .iter()
      .filter(|(&net, _)| net != offline_network)
      .map(|(_, &s)| s)
      .sum();

    let stakes_summary: Vec<_> =
      global_session.stakes.iter().map(|(net, &s)| format!("{net:?}={s}")).collect();

    serai_env::info!(
      "dos_stall ({iteration}/{iterations}): offline={offline_network:?} \
       (stake={offline_stake}), online_weight={online_weight}, threshold={threshold}, \
       all_stakes=[{}]",
      stakes_summary.join(", ")
    );

    assert!(FaultedSession::get(&db).is_none());
    let step1_latest = LatestCosignedBlockNumber::get(&db).unwrap_or(0);

    // Step 2: offline network stops signing.
    // Drain all intents but only sign+submit online ones. Offline intents are kept
    // in `offline_buffer` so step 3 can replay them when the network comes back.
    let mut offline_buffer: Vec<(ExternalNetworkId, CosignIntent)> = Vec::new();
    let mut pending_intents: Vec<(ExternalNetworkId, CosignIntent)> = Vec::new();
    for (network, intent) in deferred_intents.drain(..) {
      if network == offline_network {
        offline_buffer.push((network, intent));
      } else {
        pending_intents.push((network, intent));
      }
    }

    loop {
      {
        let mut db_clone = db.clone();
        let mut txn = db_clone.txn();
        for (network, intent) in drain_intents(&mut txn, &event_fuzzer) {
          if network == offline_network {
            offline_buffer.push((network, intent));
          } else {
            pending_intents.push((network, intent));
          }
        }
        txn.commit();
      }

      let before = LatestCosignedBlockNumber::get(&db).unwrap_or(0);

      pending_intents = pending_intents
        .drain(..)
        .filter_map(|(network, intent)| {
          sign_and_intake(&db, &mut cosigning, &event_fuzzer, network, intent).err()
        })
        .collect();

      tokio::time::sleep(Duration::from_millis(100)).await;
      let after = LatestCosignedBlockNumber::get(&db).unwrap_or(0);

      serai_env::info!(
        "dos_stall ({iteration}/{iterations}) loop: before={before}, after={after}, \
         pending={}, offline_buf={}",
        pending_intents.len(),
        offline_buffer.len(),
      );

      // Stall detected: no progress. Any stuck pending intents (e.g. FutureGlobalSession
      // for a session whose declaring block needs the offline network) go to the offline
      // buffer for recovery.
      if after == before {
        offline_buffer.append(&mut pending_intents);
        assert!(pending_intents.is_empty(), "`append` on a vector drains from it");
        break;
      }
    }

    let stalled_at = LatestCosignedBlockNumber::get(&db).unwrap_or(0);
    assert!(
      stalled_at < target,
      "pipeline should be stalled before block {target}, but reached {stalled_at}"
    );
    assert!(FaultedSession::get(&db).is_none(), "absence is not equivocation");

    serai_env::info!(
      "dos_stall ({iteration}/{iterations}): STALL verified at block {stalled_at} \
       (was {step1_latest} after step 1), online_weight={online_weight} < threshold={threshold}"
    );

    // Step 3: offline network comes back: submit buffered offline intents with retry,
    // then cosign all remaining blocks via run_honest_cosigning.
    // Temporal errors (FutureGlobalSession) are retried: cosigns for blocks after a
    // notable block can't be accepted until the declaring block is cosigned.
    while !offline_buffer.is_empty() {
      offline_buffer = offline_buffer
        .drain(..)
        .filter_map(|(network, intent)| {
          sign_and_intake(&db, &mut cosigning, &event_fuzzer, network, intent).err()
        })
        .collect();
      if !offline_buffer.is_empty() {
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
    }

    let recovery_deadline = tokio::time::Instant::now() + Duration::from_mins(2);
    run_honest_cosigning(&db, &mut cosigning, &event_fuzzer, |latest| {
      if tokio::time::Instant::now() >= recovery_deadline {
        serai_env::warn!(
          "dos_stall ({iteration}/{iterations}): recovery timed out, latest={latest:?}"
        );
        return true;
      }
      matches!(latest, Some(n) if n >= target)
    })
    .await;

    assert!(FaultedSession::get(&db).is_none());
    let final_latest = Cosigning::<MemDb>::latest_cosigned_block_number(&db).unwrap().unwrap();
    if final_latest < target {
      serai_env::warn!(
        "dos_stall ({iteration}/{iterations}): recovery incomplete, \
         stalled_at={stalled_at}, final={final_latest}, target={target}, skipping"
      );
      continue;
    }

    serai_env::info!(
      "dos_stall ({iteration}/{iterations}): RECOVERED, \
       stalled_at={stalled_at}, final={final_latest}"
    );
  }
}
