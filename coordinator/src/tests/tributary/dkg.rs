use core::time::Duration;
use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use ciphersuite::{Ciphersuite, Ristretto};
use frost::Participant;

use tokio::{time::sleep, sync::mpsc};

use serai_db::MemDb;

use processor_messages::{
  key_gen::{self, KeyGenId},
  CoordinatorMessage,
};

use tributary::{Transaction as TransactionTrait, Tributary};

use crate::{
  LocalP2p,
  tributary::{TributaryDb, Transaction, TributarySpec, scanner::handle_new_blocks},
  tests::{
    MemProcessors,
    tributary::{new_keys, new_spec, new_tributaries, run_tributaries, wait_for_tx_inclusion},
  },
};

#[tokio::test]
async fn dkg_test() {
  let keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);

  let tributaries = new_tributaries(&keys, &spec).await;

  // Run the tributaries in the background
  tokio::spawn(run_tributaries(tributaries.clone()));

  let mut txs = vec![];
  // Create DKG commitments for each key
  for key in &keys {
    let attempt = 0;
    let mut commitments = vec![0; 256];
    OsRng.fill_bytes(&mut commitments);

    let mut tx = Transaction::DkgCommitments(attempt, commitments, Transaction::empty_signed());
    tx.sign(&mut OsRng, spec.genesis(), key, 0);
    txs.push(tx);
  }

  let block_before_tx = tributaries[0].1.tip().await;

  // Publish all commitments but one
  for (i, tx) in txs.iter().enumerate().skip(1) {
    assert!(tributaries[i].1.add_transaction(tx.clone()).await);
  }

  // Wait until these are included
  for tx in txs.iter().skip(1) {
    wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, tx.hash()).await;
  }

  let expected_commitments = CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Commitments {
    id: KeyGenId { set: spec.set(), attempt: 0 },
    commitments: txs
      .iter()
      .enumerate()
      .map(|(i, tx)| {
        if let Transaction::DkgCommitments(_, commitments, _) = tx {
          (Participant::new((i + 1).try_into().unwrap()).unwrap(), commitments.clone())
        } else {
          panic!("txs had non-commitments");
        }
      })
      .collect(),
  });

  async fn new_processors(
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    spec: &TributarySpec,
    tributary: &Tributary<MemDb, Transaction, LocalP2p>,
  ) -> (TributaryDb<MemDb>, MemProcessors) {
    let mut scanner_db = TributaryDb(MemDb::new());
    let processors = MemProcessors::new();
    // Uses a brand new channel since this channel won't be used within this test
    handle_new_blocks(
      &mut scanner_db,
      key,
      &mpsc::unbounded_channel().0,
      &processors,
      spec,
      &tributary.reader(),
    )
    .await;
    (scanner_db, processors)
  }

  // Instantiate a scanner and verify it has nothing to report
  let (mut scanner_db, processors) = new_processors(&keys[0], &spec, &tributaries[0].1).await;
  assert!(processors.0.read().await.is_empty());

  // Publish the last commitment
  let block_before_tx = tributaries[0].1.tip().await;
  assert!(tributaries[0].1.add_transaction(txs[0].clone()).await);
  wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, txs[0].hash()).await;
  sleep(Duration::from_secs(Tributary::<MemDb, Transaction, LocalP2p>::block_time().into())).await;

  // Verify the scanner emits a KeyGen::Commitments message
  handle_new_blocks(
    &mut scanner_db,
    &keys[0],
    &mpsc::unbounded_channel().0,
    &processors,
    &spec,
    &tributaries[0].1.reader(),
  )
  .await;
  {
    let mut msgs = processors.0.write().await;
    assert_eq!(msgs.len(), 1);
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    assert_eq!(msgs.pop_front().unwrap(), expected_commitments);
    assert!(msgs.is_empty());
  }

  // Verify all keys exhibit this scanner behavior
  for (i, key) in keys.iter().enumerate() {
    let (_, processors) = new_processors(key, &spec, &tributaries[i].1).await;
    let mut msgs = processors.0.write().await;
    assert_eq!(msgs.len(), 1);
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    assert_eq!(msgs.pop_front().unwrap(), expected_commitments);
    assert!(msgs.is_empty());
  }

  // Now do shares
  let mut txs = vec![];
  for key in &keys {
    let attempt = 0;

    let mut shares = HashMap::new();
    for i in 0 .. keys.len() {
      let mut share = vec![0; 256];
      OsRng.fill_bytes(&mut share);
      shares.insert(Participant::new((i + 1).try_into().unwrap()).unwrap(), share);
    }

    let mut tx = Transaction::DkgShares(attempt, shares, Transaction::empty_signed());
    tx.sign(&mut OsRng, spec.genesis(), key, 1);
    txs.push(tx);
  }

  let block_before_tx = tributaries[0].1.tip().await;
  for (i, tx) in txs.iter().enumerate().skip(1) {
    assert!(tributaries[i].1.add_transaction(tx.clone()).await);
  }
  for tx in txs.iter().skip(1) {
    wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, tx.hash()).await;
  }

  // With just 4 sets of shares, nothing should happen yet
  handle_new_blocks(
    &mut scanner_db,
    &keys[0],
    &mpsc::unbounded_channel().0,
    &processors,
    &spec,
    &tributaries[0].1.reader(),
  )
  .await;
  assert_eq!(processors.0.read().await.len(), 1);
  assert!(processors.0.read().await[&spec.set().network].is_empty());

  // Publish the final set of shares
  let block_before_tx = tributaries[0].1.tip().await;
  assert!(tributaries[0].1.add_transaction(txs[0].clone()).await);
  wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, txs[0].hash()).await;
  sleep(Duration::from_secs(Tributary::<MemDb, Transaction, LocalP2p>::block_time().into())).await;

  // Each scanner should emit a distinct shares message
  let shares_for = |i: usize| {
    CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Shares {
      id: KeyGenId { set: spec.set(), attempt: 0 },
      shares: txs
        .iter()
        .enumerate()
        .map(|(l, tx)| {
          if let Transaction::DkgShares(_, shares, _) = tx {
            (
              Participant::new((l + 1).try_into().unwrap()).unwrap(),
              shares[&Participant::new((i + 1).try_into().unwrap()).unwrap()].clone(),
            )
          } else {
            panic!("txs had non-shares");
          }
        })
        .collect::<HashMap<_, _>>(),
    })
  };

  // Any scanner which has handled the prior blocks should only emit the new event
  handle_new_blocks(
    &mut scanner_db,
    &keys[0],
    &mpsc::unbounded_channel().0,
    &processors,
    &spec,
    &tributaries[0].1.reader(),
  )
  .await;
  {
    let mut msgs = processors.0.write().await;
    assert_eq!(msgs.len(), 1);
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    assert_eq!(msgs.pop_front().unwrap(), shares_for(0));
    assert!(msgs.is_empty());
  }

  // Yet new scanners should emit all events
  for (i, key) in keys.iter().enumerate() {
    let (_, processors) = new_processors(key, &spec, &tributaries[i].1).await;
    let mut msgs = processors.0.write().await;
    assert_eq!(msgs.len(), 1);
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    assert_eq!(msgs.pop_front().unwrap(), expected_commitments);
    assert_eq!(msgs.pop_front().unwrap(), shares_for(i));
    assert!(msgs.is_empty());
  }
}
