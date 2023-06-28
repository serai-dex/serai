use core::time::Duration;
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use rand_core::OsRng;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use tokio::{sync::RwLock, time::sleep};

use serai_db::MemDb;

use tributary::Tributary;

use crate::{
  tributary::Transaction,
  LocalP2p, ActiveTributary, handle_p2p, heartbeat_tributaries,
  tests::tributary::{new_keys, new_spec, new_tributaries},
};

#[tokio::test]
async fn sync_test() {
  let mut keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);
  // Ensure this can have a node fail
  assert!(spec.n() > spec.t());

  let mut tributaries = new_tributaries(&keys, &spec).await;

  // Keep a Tributary back, effectively having it offline
  let syncer_key = keys.pop().unwrap();
  let (syncer_p2p, syncer_tributary) = tributaries.pop().unwrap();

  // Have the rest form a P2P net
  let mut tributary_arcs = vec![];
  let mut p2p_threads = vec![];
  for (i, (p2p, tributary)) in tributaries.drain(..).enumerate() {
    let tributary = Arc::new(RwLock::new(tributary));
    tributary_arcs.push(tributary.clone());
    let thread = tokio::spawn(handle_p2p(
      Ristretto::generator() * *keys[i],
      p2p,
      Arc::new(RwLock::new(HashMap::from([(
        spec.genesis(),
        ActiveTributary { spec: spec.clone(), tributary },
      )]))),
    ));
    p2p_threads.push(thread);
  }
  let tributaries = tributary_arcs;

  // After three blocks of time, we should have a new block
  // We don't wait one block of time as we may have missed the chance for the first block
  // We don't wait two blocks because we may have missed the chance, and then had a failure to
  // propose by our 'offline' validator
  let block_time = u64::from(Tributary::<MemDb, Transaction, LocalP2p>::block_time());
  sleep(Duration::from_secs(3 * block_time)).await;
  let tip = tributaries[0].read().await.tip().await;
  assert!(tip != spec.genesis());

  // Sleep one second to make sure this block propagates
  sleep(Duration::from_secs(1)).await;
  // Make sure every tributary has it
  for tributary in &tributaries {
    assert!(tributary.read().await.reader().block(&tip).is_some());
  }

  // Now that we've confirmed the other tributaries formed a net without issue, drop the syncer's
  // pending P2P messages
  syncer_p2p.1.write().await.last_mut().unwrap().clear();

  // Have it join the net
  let syncer_key = Ristretto::generator() * *syncer_key;
  let syncer_tributary = Arc::new(RwLock::new(syncer_tributary));
  let syncer_tributaries = Arc::new(RwLock::new(HashMap::from([(
    spec.genesis(),
    ActiveTributary { spec: spec.clone(), tributary: syncer_tributary.clone() },
  )])));
  tokio::spawn(handle_p2p(syncer_key, syncer_p2p.clone(), syncer_tributaries.clone()));

  // It shouldn't automatically catch up. If it somehow was, our test would be broken
  // Sanity check this
  let tip = tributaries[0].read().await.tip().await;
  sleep(Duration::from_secs(2 * block_time)).await;
  assert!(tributaries[0].read().await.tip().await != tip);
  assert_eq!(syncer_tributary.read().await.tip().await, spec.genesis());

  // Start the heartbeat protocol
  tokio::spawn(heartbeat_tributaries(syncer_p2p, syncer_tributaries));

  // The heartbeat is once every 10 blocks
  sleep(Duration::from_secs(10 * block_time)).await;
  assert!(syncer_tributary.read().await.tip().await != spec.genesis());

  // Verify it synced to the tip
  let syncer_tip = {
    let tributary = tributaries[0].write().await;
    let syncer_tributary = syncer_tributary.write().await;

    let tip = tributary.tip().await;
    let syncer_tip = syncer_tributary.tip().await;
    // Allow a one block tolerance in case of race conditions
    assert!(
      HashSet::from([tip, tributary.reader().block(&tip).unwrap().parent()]).contains(&syncer_tip)
    );
    syncer_tip
  };

  sleep(Duration::from_secs(block_time)).await;

  // Verify it's now keeping up
  assert!(syncer_tributary.read().await.tip().await != syncer_tip);

  // Verify it's now participating in consensus
  // Because only `t` validators are used in a commit, take n - t nodes offline
  // leaving only `t` nodes. Which should force it to participate in the consensus
  // of next blocks.
  let n = (spec.n() - spec.t()) as usize;
  for t in p2p_threads.iter().take(n) {
    t.abort();
  }

  // wait for a block
  sleep(Duration::from_secs(block_time)).await;

  let syncer_tributary = syncer_tributary.read().await;
  if syncer_tributary
    .reader()
    .parsed_commit(&syncer_tributary.tip().await)
    .unwrap()
    .validators
    .iter()
    .any(|signer| signer == &syncer_key.to_bytes())
  {
    return;
  }

  panic!("synced tributary didn't start participating in consensus");
}
