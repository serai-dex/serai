use core::time::Duration;
use std::collections::HashMap;

use rand_core::OsRng;

use tokio::time::timeout;

use crate::{
  Plan,
  coins::{OutputType, Output, Block, Coin},
  scanner::{ScannerOrder, ScannerEvent, Scanner},
  tests::{util::db::MemDb, sign},
};

pub async fn test_addresses<C: Coin>(coin: C) {
  let mut keys = frost::tests::key_gen::<_, C::Curve>(&mut OsRng);
  for (_, keys) in keys.iter_mut() {
    C::tweak_keys(keys);
  }
  let key = keys[&1].group_key();

  // Mine blocks so there's a confirmed block
  for _ in 0 .. C::CONFIRMATIONS {
    coin.mine_block().await;
  }

  let db = MemDb::new();
  let (mut scanner, active_keys) = Scanner::new(coin.clone(), db.clone());
  assert!(active_keys.is_empty());
  scanner
    .orders
    .send(ScannerOrder::RotateKey {
      activation_number: coin.get_latest_block_number().await.unwrap(),
      key,
    })
    .unwrap();

  // Receive funds to the branch address and make sure it's properly identified
  let block_id = coin.test_send(C::branch_address(key)).await.id();

  // Verify the Scanner picked them up
  let outputs =
    match timeout(Duration::from_secs(10), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Outputs(this_key, block, outputs) => {
        assert_eq!(this_key, key);
        assert_eq!(block, block_id);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].kind(), OutputType::Branch);
        outputs
      }
    };

  // Trigger a send with change and ensure we actually get change
  let mut keys_txs = HashMap::new();
  for (i, keys) in keys {
    keys_txs.insert(
      i,
      (
        keys.clone(),
        coin
          .prepare_send(
            keys,
            coin.get_latest_block_number().await.unwrap() - C::CONFIRMATIONS,
            Plan { key, inputs: outputs.clone(), payments: vec![], change: Some(key) },
            coin.get_fee().await,
          )
          .await
          .unwrap()
          .0,
      ),
    );
  }
  sign(coin.clone(), keys_txs).await;

  for _ in 0 .. C::CONFIRMATIONS {
    coin.mine_block().await;
  }
  match timeout(Duration::from_secs(10), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Outputs(this_key, _, outputs) => {
      assert_eq!(this_key, key);
      assert_eq!(outputs.len(), 1);
      assert_eq!(outputs[0].kind(), OutputType::Change);
    }
  };
}
