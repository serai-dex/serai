use std::{time::Duration, collections::HashMap};

use rand_core::OsRng;

use transcript::{Transcript, RecommendedTranscript};
use frost::dkg::tests::key_gen;

use tokio::time::timeout;

use crate::{
  Payment, Plan,
  coin::{Output, Block, Coin},
  scanner::{ScannerOrder, ScannerEvent, Scanner},
  scheduler::Scheduler,
  tests::{util::db::MemDb, sign},
};

// Tests the Scanner, Scheduler, and Signer together
pub async fn test_wallet<C: Coin>(coin: C) {
  let mut keys = key_gen(&mut OsRng);
  for (_, keys) in keys.iter_mut() {
    C::tweak_keys(keys);
  }
  let key = keys[&1].group_key();

  let (sync_block, outputs) = {
    let mut scanner = Scanner::new(coin.clone(), MemDb::new());
    scanner
      .orders
      .send(ScannerOrder::RotateKey {
        activation_number: coin.get_latest_block_number().await.unwrap(),
        key,
      })
      .unwrap();

    // Sanity check the test_send return value while hre
    let next_number = coin.get_latest_block_number().await.unwrap();
    let block_id = coin.test_send(C::address(key)).await.id();
    assert_eq!(coin.get_block(next_number).await.unwrap().id(), block_id);

    match timeout(Duration::from_secs(5), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Block(number, id) => {
        assert_eq!(number, next_number);
        assert_eq!(id, block_id);
      }
      _ => panic!("unexpected event"),
    };

    match timeout(Duration::from_secs(5), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Outputs(this_key, block, outputs) => {
        assert_eq!(this_key, key);
        assert_eq!(block, block_id);
        (next_number, outputs)
      }
      _ => panic!("unexpeced event"),
    }
  };

  let mut scheduler = Scheduler::new(key);
  // Add these outputs, which should return no plans
  assert!(scheduler.add_outputs(outputs.clone()).is_empty());

  #[allow(clippy::inconsistent_digit_grouping)]
  let amount = 1_00_000_000;
  let mut plans = scheduler.schedule(vec![Payment { address: C::address(key), amount }]);
  assert_eq!(
    plans,
    vec![Plan {
      inputs: outputs,
      payments: vec![Payment { address: C::address(key), amount }],
      change: true,
    }]
  );

  // Execute the plan
  let fee = coin.get_fee().await;
  let mut params_txs = HashMap::new();
  for (i, keys) in keys.drain() {
    params_txs.insert(
      i,
      (
        keys.params(),
        coin
          .prepare_send(
            keys,
            RecommendedTranscript::new(b"Processor Wallet Test"),
            sync_block,
            plans.swap_remove(0),
            key,
            fee,
          )
          .await
          .unwrap(),
      ),
    );
  }

  sign(coin.clone(), params_txs).await;
  coin.mine_block().await;
  let outputs = coin
    .get_outputs(&coin.get_block(coin.get_latest_block_number().await.unwrap()).await.unwrap(), key)
    .await
    .unwrap();
  assert_eq!(outputs.len(), 2);
  assert!((outputs[0].amount() == amount) || (outputs[1].amount() == amount));
}
