use core::time::Duration;
use std::{sync::Arc, collections::HashSet};

use rand_core::OsRng;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use tokio::{
  sync::{mpsc, broadcast},
  time::sleep,
};

use serai_db::MemDb;

use tributary::Tributary;

use crate::{
  tributary::Transaction,
  ActiveTributary, TributaryEvent,
  p2p::{heartbeat_tributaries_task, handle_p2p_task},
  tests::{
    LocalP2p,
    tributary::{new_keys, new_spec, new_tributaries},
  },
};

#[tokio::test]
async fn sync_test() {
  let mut keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);
  // Ensure this can have a node fail
  assert!(spec.n() > spec.t());

  let mut tributaries = new_tributaries(&keys, &spec)
    .await
    .into_iter()
    .map(|(_, p2p, tributary)| (p2p, tributary))
    .collect::<Vec<_>>();

  // Keep a Tributary back, effectively having it offline
  let syncer_key = keys.pop().unwrap();
  let (syncer_p2p, syncer_tributary) = tributaries.pop().unwrap();

  // Have the rest form a P2P net
  let mut tributary_senders = vec![];
  let mut tributary_arcs = vec![];
  let mut p2p_threads = vec![];
  for (p2p, tributary) in tributaries.drain(..) {
    let tributary = Arc::new(tributary);
    tributary_arcs.push(tributary.clone());
    let (new_tributary_send, new_tributary_recv) = broadcast::channel(5);
    let (cosign_send, _) = mpsc::unbounded_channel();
    let thread = tokio::spawn(handle_p2p_task(p2p, cosign_send, new_tributary_recv));
    new_tributary_send
      .send(TributaryEvent::NewTributary(ActiveTributary { spec: spec.clone(), tributary }))
      .map_err(|_| "failed to send ActiveTributary")
      .unwrap();
    tributary_senders.push(new_tributary_send);
    p2p_threads.push(thread);
  }
  let tributaries = tributary_arcs;

  // After four blocks of time, we should have a new block
  // We don't wait one block of time as we may have missed the chance for the first block
  // We don't wait two blocks because we may have missed the chance, and then had a failure to
  // propose by our 'offline' validator, which would cause the Tendermint round time to increase,
  // requiring a longer delay
  let block_time = u64::from(Tributary::<MemDb, Transaction, LocalP2p>::block_time());
  sleep(Duration::from_secs(4 * block_time)).await;
  let tip = tributaries[0].tip().await;
  assert!(tip != spec.genesis());

  // Sleep one second to make sure this block propagates
  sleep(Duration::from_secs(1)).await;
  // Make sure every tributary has it
  for tributary in &tributaries {
    assert!(tributary.reader().block(&tip).is_some());
  }

  // Now that we've confirmed the other tributaries formed a net without issue, drop the syncer's
  // pending P2P messages
  syncer_p2p.1.write().await.1.last_mut().unwrap().clear();

  // Have it join the net
  let syncer_key = Ristretto::generator() * *syncer_key;
  let syncer_tributary = Arc::new(syncer_tributary);
  let (syncer_tributary_send, syncer_tributary_recv) = broadcast::channel(5);
  let (cosign_send, _) = mpsc::unbounded_channel();
  tokio::spawn(handle_p2p_task(syncer_p2p.clone(), cosign_send, syncer_tributary_recv));
  syncer_tributary_send
    .send(TributaryEvent::NewTributary(ActiveTributary {
      spec: spec.clone(),
      tributary: syncer_tributary.clone(),
    }))
    .map_err(|_| "failed to send ActiveTributary to syncer")
    .unwrap();

  // It shouldn't automatically catch up. If it somehow was, our test would be broken
  // Sanity check this
  let tip = tributaries[0].tip().await;
  // Wait until a new block occurs
  sleep(Duration::from_secs(3 * block_time)).await;
  // Make sure a new block actually occurred
  assert!(tributaries[0].tip().await != tip);
  // Make sure the new block alone didn't trigger catching up
  assert_eq!(syncer_tributary.tip().await, spec.genesis());

  // Start the heartbeat protocol
  let (syncer_heartbeat_tributary_send, syncer_heartbeat_tributary_recv) = broadcast::channel(5);
  tokio::spawn(heartbeat_tributaries_task(syncer_p2p, syncer_heartbeat_tributary_recv));
  syncer_heartbeat_tributary_send
    .send(TributaryEvent::NewTributary(ActiveTributary {
      spec: spec.clone(),
      tributary: syncer_tributary.clone(),
    }))
    .map_err(|_| "failed to send ActiveTributary to heartbeat")
    .unwrap();

  // The heartbeat is once every 10 blocks, with some limitations
  sleep(Duration::from_secs(20 * block_time)).await;
  assert!(syncer_tributary.tip().await != spec.genesis());

  // Verify it synced to the tip
  let syncer_tip = {
    let tributary = &tributaries[0];

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
  assert!(syncer_tributary.tip().await != syncer_tip);

  // Verify it's now participating in consensus
  // Because only `t` validators are used in a commit, take n - t nodes offline
  // leaving only `t` nodes. Which should force it to participate in the consensus
  // of next blocks.
  let spares = usize::from(spec.n() - spec.t());
  for thread in p2p_threads.iter().take(spares) {
    thread.abort();
  }

  // wait for a block
  sleep(Duration::from_secs(block_time)).await;

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
