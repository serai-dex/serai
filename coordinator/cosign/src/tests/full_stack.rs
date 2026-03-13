use std::{collections::HashSet, time::Duration};

use serai_db::{Db as _, DbTxn, MemDb};

use serai_cosign_types::tests::sign_cosign;

use serai_client_serai::abi::primitives::{
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
};

use crate::{
  CosignIntent, Cosigning, GlobalSessions, IntakeCosignError,
  tests::{TestRequest, setup_shim_serai},
};

#[tokio::test]
async fn full_stack_fuzzed() {
  use super::intend::EventFuzzer;

  let _ = env_logger::try_init();

  let num_blocks = 20;
  let mut fuzzer = EventFuzzer::new();
  let blocks = fuzzer.generate_blocks(num_blocks);

  serai_log::log::info!(
    "Full-stack fuzz: {} blocks, {} validators, seed={}",
    num_blocks,
    fuzzer.validators.len(),
    hex::encode(fuzzer.seed),
  );

  let (shim, serai) = setup_shim_serai().await;
  for (i, events) in blocks.into_iter().enumerate() {
    shim.make_block(u64::try_from(i).unwrap(), events).await;
  }

  let mut db = MemDb::new();

  let (request, _calls) = TestRequest::new(false);
  let mut cosigning = Cosigning::spawn(db.clone(), serai, request, vec![]);

  let target = u64::try_from(num_blocks - 1).unwrap();

  // Buffer for intents whose cosigns were rejected as FutureGlobalSession.
  // These are retried each iteration until the delay task catches up.
  let mut pending_intents: Vec<(ExternalNetworkId, CosignIntent)> = Vec::new();
  let mut seen_global_sessions: HashSet<[u8; 32]> = HashSet::new();

  let deadline = tokio::time::Instant::now() + Duration::from_secs(300);

  loop {
    assert!(
      tokio::time::Instant::now() < deadline,
      "timed out waiting for all blocks to be cosigned (target={target}, \
       latest={:?}, pending_intents={})",
      Cosigning::<MemDb>::latest_acknowledged_block(&db),
      pending_intents.len(),
    );

    // Drain new intended cosigns for all validator sets that have had SetKeys
    {
      let mut txn = db.txn();
      for network in ExternalNetworkId::all() {
        let max_session = fuzzer.next_session.get(&network).copied().unwrap_or(0);
        for session_num in 0 .. max_session {
          let set = ExternalValidatorSet { network, session: Session(session_num) };
          let intents = Cosigning::<MemDb>::intended_cosigns(&mut txn, set);
          for intent in intents {
            seen_global_sessions.insert(intent.global_session);
            pending_intents.push((network, intent));
          }
        }
      }
      txn.commit();
    }

    // Try to intake all pending intents, keeping those that fail with temporal errors
    let mut still_pending = Vec::new();
    for (network, intent) in pending_intents.drain(..) {
      let cosign = intent.into_cosign(network);
      let Some(gs) = GlobalSessions::get(&db, intent.global_session) else {
        still_pending.push((network, intent));
        continue;
      };
      let Some(public) = gs.keys.get(&network) else { continue };
      let Some(keypair) = fuzzer.keypairs.get(&public.0) else { continue };
      let signed = sign_cosign(cosign, keypair);
      match cosigning.intake_cosign(&signed) {
        Ok(()) => {}
        Err(IntakeCosignError::FutureGlobalSession) |
        Err(IntakeCosignError::UnrecognizedGlobalSession) |
        Err(IntakeCosignError::NotYetIndexedBlock) => {
          still_pending.push((network, intent));
        }
        // StaleCosign means a newer cosign already exists; safe to drop
        Err(IntakeCosignError::StaleCosign) => {}
        Err(ref e) => {
          serai_log::log::warn!(
            "intake_cosign dropped: block={}, network={:?}, err={:?}",
            intent.block_number,
            network,
            e,
          );
        }
      }
    }
    pending_intents = still_pending;

    match Cosigning::<MemDb>::latest_acknowledged_block(&db) {
      Ok(n) if n >= target => break,
      _ => {}
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
  }

  let latest = Cosigning::<MemDb>::latest_acknowledged_block(&db).unwrap();
  assert!(latest >= target, "expected latest cosigned block >= {target}, got {latest}");

  serai_log::log::info!("Full-stack fuzz completed: all {num_blocks} blocks cosigned");

  let session_ids: Vec<[u8; 32]> = seen_global_sessions.into_iter().collect();
}
