use core::time::Duration;
use std::collections::HashMap;

use rand_core::OsRng;

use frost::{Participant, ThresholdKeys};

use tokio::time::timeout;

use serai_db::{DbTxn, MemDb};

use crate::{
  Plan, Db,
  networks::{OutputType, Output, Block, Network},
  scanner::{ScannerEvent, Scanner, ScannerHandle},
  tests::sign,
};

async fn spend<N: Network, D: Db>(
  network: &N,
  keys: &HashMap<Participant, ThresholdKeys<N::Curve>>,
  scanner: &mut ScannerHandle<N, D>,
  outputs: Vec<N::Output>,
) -> Vec<N::Output> {
  let key = keys[&Participant::new(1).unwrap()].group_key();

  let mut keys_txs = HashMap::new();
  for (i, keys) in keys {
    keys_txs.insert(
      *i,
      (
        keys.clone(),
        network
          .prepare_send(
            keys.clone(),
            network.get_latest_block_number().await.unwrap() - N::CONFIRMATIONS,
            // Send to a change output
            Plan { key, inputs: outputs.clone(), payments: vec![], change: Some(key) },
            network.get_fee().await,
          )
          .await
          .unwrap()
          .0
          .unwrap(),
      ),
    );
  }
  sign(network.clone(), keys_txs).await;

  for _ in 0 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }
  match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Block { block: _, outputs } => {
      assert_eq!(outputs.len(), 1);
      // Make sure this is actually a change output
      assert_eq!(outputs[0].kind(), OutputType::Change);
      outputs
    }
    ScannerEvent::Completed(_, _) => {
      panic!("unexpectedly got eventuality completion");
    }
  }
}

pub async fn test_addresses<N: Network>(network: N) {
  let mut keys = frost::tests::key_gen::<_, N::Curve>(&mut OsRng);
  for (_, keys) in keys.iter_mut() {
    N::tweak_keys(keys);
  }
  let key = keys[&Participant::new(1).unwrap()].group_key();

  // Mine blocks so there's a confirmed block
  for _ in 0 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }

  let mut db = MemDb::new();
  let (mut scanner, active_keys) = Scanner::new(network.clone(), db.clone());
  assert!(active_keys.is_empty());
  let mut txn = db.txn();
  scanner.rotate_key(&mut txn, network.get_latest_block_number().await.unwrap(), key).await;
  txn.commit();

  // Receive funds to the branch address and make sure it's properly identified
  let block_id = network.test_send(N::branch_address(key)).await.id();

  // Verify the Scanner picked them up
  let outputs =
    match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Block { block, outputs } => {
        assert_eq!(block, block_id);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].kind(), OutputType::Branch);
        outputs
      }
      ScannerEvent::Completed(_, _) => {
        panic!("unexpectedly got eventuality completion");
      }
    };

  // Spend the branch output, creating a change output and ensuring we actually get change
  let outputs = spend(&network, &keys, &mut scanner, outputs).await;
  // Also test spending the change output
  spend(&network, &keys, &mut scanner, outputs).await;
}
