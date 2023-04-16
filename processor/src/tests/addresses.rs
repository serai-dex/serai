use core::time::Duration;
use std::collections::HashMap;

use rand_core::OsRng;

use frost::{Participant, ThresholdKeys};

use tokio::time::timeout;

use serai_db::MemDb;

use crate::{
  Plan, Db,
  coins::{OutputType, Output, Block, Coin},
  scanner::{ScannerEvent, Scanner, ScannerHandle},
  tests::sign,
};

async fn spend<C: Coin, D: Db>(
  coin: &C,
  keys: &HashMap<Participant, ThresholdKeys<C::Curve>>,
  scanner: &mut ScannerHandle<C, D>,
  batch: u32,
  outputs: Vec<C::Output>,
) -> Vec<C::Output> {
  let key = keys[&Participant::new(1).unwrap()].group_key();

  let mut keys_txs = HashMap::new();
  for (i, keys) in keys {
    keys_txs.insert(
      *i,
      (
        keys.clone(),
        coin
          .prepare_send(
            keys.clone(),
            coin.get_latest_block_number().await.unwrap() - C::CONFIRMATIONS,
            // Send to a change output
            Plan { key, inputs: outputs.clone(), payments: vec![], change: Some(key) },
            coin.get_fee().await,
          )
          .await
          .unwrap()
          .0
          .unwrap(),
      ),
    );
  }
  sign(coin.clone(), keys_txs).await;

  for _ in 0 .. C::CONFIRMATIONS {
    coin.mine_block().await;
  }
  match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Block { key: this_key, block: _, batch: this_batch, outputs } => {
      assert_eq!(this_key, key);
      assert_eq!(this_batch, batch);
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

pub async fn test_addresses<C: Coin>(coin: C) {
  let mut keys = frost::tests::key_gen::<_, C::Curve>(&mut OsRng);
  for (_, keys) in keys.iter_mut() {
    C::tweak_keys(keys);
  }
  let key = keys[&Participant::new(1).unwrap()].group_key();

  // Mine blocks so there's a confirmed block
  for _ in 0 .. C::CONFIRMATIONS {
    coin.mine_block().await;
  }

  let db = MemDb::new();
  let (mut scanner, active_keys) = Scanner::new(coin.clone(), db.clone());
  assert!(active_keys.is_empty());
  scanner.rotate_key(coin.get_latest_block_number().await.unwrap(), key).await;

  // Receive funds to the branch address and make sure it's properly identified
  let block_id = coin.test_send(C::branch_address(key)).await.id();

  // Verify the Scanner picked them up
  let outputs =
    match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Block { key: this_key, block, batch, outputs } => {
        assert_eq!(this_key, key);
        assert_eq!(block, block_id);
        assert_eq!(batch, 0);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].kind(), OutputType::Branch);
        outputs
      }
      ScannerEvent::Completed(_, _) => {
        panic!("unexpectedly got eventuality completion");
      }
    };

  // Spend the branch output, creating a change output and ensuring we actually get change
  let outputs = spend(&coin, &keys, &mut scanner, 1, outputs).await;
  // Also test spending the change output
  spend(&coin, &keys, &mut scanner, 2, outputs).await;
}
