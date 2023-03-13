use core::time::Duration;
use std::sync::{Arc, Mutex};

use rand_core::OsRng;

use tokio::time::{sleep, timeout};

use crate::{
  coins::{OutputType, Output, Block, Coin},
  scanner::{ScannerOrder, ScannerEvent, Scanner, ScannerHandle},
  tests::util::db::MemDb,
};

pub async fn test_scanner<C: Coin>(coin: C) {
  let mut keys = frost::tests::key_gen::<_, C::Curve>(&mut OsRng).remove(&1).unwrap();
  C::tweak_keys(&mut keys);

  // Mine blocks so there's a confirmed block
  for _ in 0 .. C::CONFIRMATIONS {
    coin.mine_block().await;
  }

  let first = Arc::new(Mutex::new(true));
  let db = MemDb::new();
  let new_scanner = || async {
    let (scanner, active_keys) = Scanner::new(coin.clone(), db.clone());
    let mut first = first.lock().unwrap();
    if *first {
      assert!(active_keys.is_empty());
      scanner
        .handle(ScannerOrder::RotateKey {
          activation_number: coin.get_latest_block_number().await.unwrap(),
          key: keys.group_key(),
        })
        .await;
      *first = false;
    } else {
      assert_eq!(active_keys.len(), 1);
    }
    scanner
  };
  let scanner = new_scanner().await;

  // Receive funds
  let block_id = coin.test_send(C::address(keys.group_key())).await.id();

  // Verify the Scanner picked them up
  let verify_event = |mut scanner: ScannerHandle<C, MemDb>| async {
    let outputs =
      match timeout(Duration::from_secs(10), scanner.events.recv()).await.unwrap().unwrap() {
        ScannerEvent::Outputs(key, block, outputs) => {
          assert_eq!(key, keys.group_key());
          assert_eq!(block, block_id);
          assert_eq!(outputs.len(), 1);
          assert_eq!(outputs[0].kind(), OutputType::External);
          outputs
        }
      };
    (scanner, outputs)
  };
  let (mut scanner, outputs) = verify_event(scanner).await;

  // Create a new scanner off the current DB and verify it re-emits the above events
  verify_event(new_scanner().await).await;

  // Acknowledge the block
  scanner.handle(ScannerOrder::AckBlock(keys.group_key(), block_id.clone())).await;
  sleep(Duration::from_secs(1)).await;
  assert_eq!(scanner.outputs(&keys.group_key(), &block_id).await, outputs);

  // There should be no more events
  assert!(timeout(Duration::from_secs(10), scanner.events.recv()).await.is_err());

  // Create a new scanner off the current DB and make sure it also does nothing
  assert!(timeout(Duration::from_secs(10), new_scanner().await.events.recv()).await.is_err());
}
