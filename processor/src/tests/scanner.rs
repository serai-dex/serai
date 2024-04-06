use core::time::Duration;
use std::sync::Arc;

use ciphersuite::Ciphersuite;
use rand_core::OsRng;

use frost::{Participant, tests::key_gen};

use tokio::{sync::Mutex, time::timeout};

use serai_db::{DbTxn, Db, MemDb};

use crate::{
  networks::{OutputType, Output, Block, UtxoNetwork},
  multisigs::scanner::{ScannerEvent, Scanner, ScannerHandle},
};

pub async fn new_scanner<N: UtxoNetwork, D: Db>(
  network: &N,
  db: &D,
  group_key: <N::Curve as Ciphersuite>::G,
  first: &Arc<Mutex<bool>>,
) -> ScannerHandle<N, D> {
  let activation_number = network.get_latest_block_number().await.unwrap();
  let mut db = db.clone();
  let (mut scanner, current_keys) = Scanner::new(network.clone(), db.clone());
  let mut first = first.lock().await;
  if *first {
    assert!(current_keys.is_empty());
    let mut txn = db.txn();
    scanner.register_key(&mut txn, activation_number, group_key).await;
    txn.commit();
    for _ in 0 .. N::CONFIRMATIONS {
      network.mine_block().await;
    }
    *first = false;
  } else {
    assert_eq!(current_keys.len(), 1);
  }
  scanner
}

pub async fn test_scanner<N: UtxoNetwork>(network: N) {
  let mut keys =
    frost::tests::key_gen::<_, N::Curve>(&mut OsRng).remove(&Participant::new(1).unwrap()).unwrap();
  N::tweak_keys(&mut keys);
  let group_key = keys.group_key();

  // Mine blocks so there's a confirmed block
  for _ in 0 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }

  let db = MemDb::new();
  let first = Arc::new(Mutex::new(true));
  let scanner = new_scanner(&network, &db, group_key, &first).await;

  // Receive funds
  let block = network.test_send(N::external_address(&network, keys.group_key())).await;
  let block_id = block.id();

  // Verify the Scanner picked them up
  let verify_event = |mut scanner: ScannerHandle<N, MemDb>| async {
    let outputs =
      match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
        ScannerEvent::Block { is_retirement_block, block, outputs } => {
          scanner.multisig_completed.send(false).unwrap();
          assert!(!is_retirement_block);
          assert_eq!(block, block_id);
          assert_eq!(outputs.len(), 1);
          assert_eq!(outputs[0].kind(), OutputType::External);
          outputs
        }
        ScannerEvent::Completed(_, _, _, _, _) => {
          panic!("unexpectedly got eventuality completion");
        }
      };
    (scanner, outputs)
  };
  let (mut scanner, outputs) = verify_event(scanner).await;

  // Create a new scanner off the current DB and verify it re-emits the above events
  verify_event(new_scanner(&network, &db, group_key, &first).await).await;

  // Acknowledge the block
  let mut cloned_db = db.clone();
  let mut txn = cloned_db.txn();
  assert_eq!(scanner.ack_block(&mut txn, block_id).await.1, outputs);
  scanner.release_lock().await;
  txn.commit();

  // There should be no more events
  assert!(timeout(Duration::from_secs(30), scanner.events.recv()).await.is_err());

  // Create a new scanner off the current DB and make sure it also does nothing
  assert!(timeout(
    Duration::from_secs(30),
    new_scanner(&network, &db, group_key, &first).await.events.recv()
  )
  .await
  .is_err());
}

pub async fn test_no_deadlock_in_multisig_completed<N: UtxoNetwork>(network: N) {
  // Mine blocks so there's a confirmed block
  for _ in 0 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }

  let mut db = MemDb::new();
  let (mut scanner, current_keys) = Scanner::new(network.clone(), db.clone());
  assert!(current_keys.is_empty());

  let mut txn = db.txn();
  // Register keys to cause Block events at CONFIRMATIONS (dropped since first keys),
  // CONFIRMATIONS + 1, and CONFIRMATIONS + 2
  for i in 0 .. 3 {
    scanner
      .register_key(
        &mut txn,
        network.get_latest_block_number().await.unwrap() + N::CONFIRMATIONS + i,
        {
          let mut keys = key_gen(&mut OsRng);
          for keys in keys.values_mut() {
            N::tweak_keys(keys);
          }
          keys[&Participant::new(1).unwrap()].group_key()
        },
      )
      .await;
  }
  txn.commit();

  for _ in 0 .. (3 * N::CONFIRMATIONS) {
    network.mine_block().await;
  }

  let block_id =
    match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Block { is_retirement_block, block, outputs: _ } => {
        scanner.multisig_completed.send(false).unwrap();
        assert!(!is_retirement_block);
        block
      }
      ScannerEvent::Completed(_, _, _, _, _) => {
        panic!("unexpectedly got eventuality completion");
      }
    };

  match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Block { .. } => {}
    ScannerEvent::Completed(_, _, _, _, _) => {
      panic!("unexpectedly got eventuality completion");
    }
  };

  // The ack_block acquisition shows the Scanner isn't maintaining the lock on its own thread after
  // emitting the Block event
  // TODO: This is incomplete. Also test after emitting Completed
  let mut txn = db.txn();
  assert_eq!(scanner.ack_block(&mut txn, block_id).await.1, vec![]);
  scanner.release_lock().await;
  txn.commit();

  scanner.multisig_completed.send(false).unwrap();
}
