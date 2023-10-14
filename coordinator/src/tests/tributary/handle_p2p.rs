use core::time::Duration;
use std::sync::Arc;

use rand_core::OsRng;

use ciphersuite::{Ciphersuite, Ristretto};

use tokio::{sync::broadcast, time::sleep};

use serai_db::MemDb;

use tributary::Tributary;

use crate::{
  tributary::Transaction,
  ActiveTributary, TributaryEvent,
  p2p::handle_p2p_task,
  tests::{
    LocalP2p,
    tributary::{new_keys, new_spec, new_tributaries},
  },
};

#[tokio::test]
async fn handle_p2p_test() {
  let keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);

  let mut tributaries = new_tributaries(&keys, &spec).await;

  let mut tributary_senders = vec![];
  let mut tributary_arcs = vec![];
  for (i, (p2p, tributary)) in tributaries.drain(..).enumerate() {
    let tributary = Arc::new(tributary);
    tributary_arcs.push(tributary.clone());
    let (new_tributary_send, new_tributary_recv) = broadcast::channel(5);
    tokio::spawn(handle_p2p_task(Ristretto::generator() * *keys[i], p2p, new_tributary_recv));
    new_tributary_send
      .send(TributaryEvent::NewTributary(ActiveTributary { spec: spec.clone(), tributary }))
      .map_err(|_| "failed to send ActiveTributary")
      .unwrap();
    tributary_senders.push(new_tributary_send);
  }
  let tributaries = tributary_arcs;

  // After two blocks of time, we should have a new block
  // We don't wait one block of time as we may have missed the chance for this block
  sleep(Duration::from_secs((2 * Tributary::<MemDb, Transaction, LocalP2p>::block_time()).into()))
    .await;
  let tip = tributaries[0].tip().await;
  assert!(tip != spec.genesis());

  // Sleep one second to make sure this block propagates
  sleep(Duration::from_secs(1)).await;
  // Make sure every tributary has it
  for tributary in &tributaries {
    assert!(tributary.reader().block(&tip).is_some());
  }

  // Then after another block of time, we should have yet another new block
  sleep(Duration::from_secs(Tributary::<MemDb, Transaction, LocalP2p>::block_time().into())).await;
  let new_tip = tributaries[0].tip().await;
  assert!(new_tip != tip);
  sleep(Duration::from_secs(1)).await;
  for tributary in tributaries {
    assert!(tributary.reader().block(&new_tip).is_some());
  }
}
