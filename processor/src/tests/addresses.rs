use core::time::Duration;
use std::collections::HashMap;

use rand_core::OsRng;

use frost::{Participant, ThresholdKeys};

use tokio::time::timeout;

use serai_client::validator_sets::primitives::Session;

use serai_db::{DbTxn, MemDb};

use crate::{
  Plan, Db,
  networks::{OutputType, Output, Block, Network},
  multisigs::scanner::{ScannerEvent, Scanner, ScannerHandle},
  tests::sign,
};

async fn spend<N: Network, D: Db>(
  db: &mut D,
  network: &N,
  keys: &HashMap<Participant, ThresholdKeys<N::Curve>>,
  scanner: &mut ScannerHandle<N, D>,
  outputs: Vec<N::Output>,
) {
  let key = keys[&Participant::new(1).unwrap()].group_key();

  let mut keys_txs = HashMap::new();
  for (i, keys) in keys {
    keys_txs.insert(
      *i,
      (
        keys.clone(),
        network
          .prepare_send(
            network.get_latest_block_number().await.unwrap() - N::CONFIRMATIONS,
            // Send to a change output
            Plan {
              key,
              inputs: outputs.clone(),
              payments: vec![],
              change: Some(N::change_address(key)),
            },
            0,
          )
          .await
          .unwrap()
          .tx
          .unwrap(),
      ),
    );
  }
  sign(network.clone(), Session(0), keys_txs).await;

  for _ in 0 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }
  match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Block { is_retirement_block, block, outputs } => {
      scanner.multisig_completed.send(false).unwrap();
      assert!(!is_retirement_block);
      assert_eq!(outputs.len(), 1);
      // Make sure this is actually a change output
      assert_eq!(outputs[0].kind(), OutputType::Change);
      assert_eq!(outputs[0].key(), key);
      let mut txn = db.txn();
      assert_eq!(scanner.ack_block(&mut txn, block).await.1, outputs);
      scanner.release_lock().await;
      txn.commit();
    }
    ScannerEvent::Completed(_, _, _, _, _) => {
      panic!("unexpectedly got eventuality completion");
    }
  }
}

pub async fn test_addresses<N: Network>(network: N) {
  let mut keys = frost::tests::key_gen::<_, N::Curve>(&mut OsRng);
  for keys in keys.values_mut() {
    N::tweak_keys(keys);
  }
  let key = keys[&Participant::new(1).unwrap()].group_key();

  // Mine blocks so there's a confirmed block
  for _ in 0 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }

  let mut db = MemDb::new();
  let (mut scanner, current_keys) = Scanner::new(network.clone(), db.clone());
  assert!(current_keys.is_empty());
  let mut txn = db.txn();
  scanner.register_key(&mut txn, network.get_latest_block_number().await.unwrap(), key).await;
  txn.commit();
  for _ in 0 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }

  // Receive funds to the various addresses and make sure they're properly identified
  let mut received_outputs = vec![];
  for (kind, address) in [
    (OutputType::External, N::external_address(key)),
    (OutputType::Branch, N::branch_address(key)),
    (OutputType::Change, N::change_address(key)),
    (OutputType::Forwarded, N::forward_address(key)),
  ] {
    let block_id = network.test_send(address).await.id();

    // Verify the Scanner picked them up
    match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Block { is_retirement_block, block, outputs } => {
        scanner.multisig_completed.send(false).unwrap();
        assert!(!is_retirement_block);
        assert_eq!(block, block_id);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].kind(), kind);
        assert_eq!(outputs[0].key(), key);
        let mut txn = db.txn();
        assert_eq!(scanner.ack_block(&mut txn, block).await.1, outputs);
        scanner.release_lock().await;
        txn.commit();
        received_outputs.extend(outputs);
      }
      ScannerEvent::Completed(_, _, _, _, _) => {
        panic!("unexpectedly got eventuality completion");
      }
    };
  }

  // Spend the branch output, creating a change output and ensuring we actually get change
  spend(&mut db, &network, &keys, &mut scanner, received_outputs).await;
}
