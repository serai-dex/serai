use std::{time::Duration, collections::HashMap};

use rand_core::OsRng;

use group::GroupEncoding;
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

  let (mut scanner, active_keys) = Scanner::new(coin.clone(), MemDb::new());
  assert!(active_keys.is_empty());
  let (sync_block, outputs) = {
    scanner
      .orders
      .send(ScannerOrder::RotateKey {
        activation_number: coin.get_latest_block_number().await.unwrap(),
        key,
      })
      .unwrap();

    let block_id = coin.test_send(C::address(key)).await.id();

    let block_number;
    match timeout(Duration::from_secs(10), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Block(number, id) => {
        assert_eq!(coin.get_block(number).await.unwrap().id(), block_id);
        assert_eq!(id, block_id);
        block_number = number;
      }
      _ => panic!("unexpected event"),
    };

    match timeout(Duration::from_secs(1), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Outputs(this_key, block, outputs) => {
        assert_eq!(this_key, key);
        assert_eq!(block, block_id);
        assert_eq!(outputs.len(), 1);
        (block_number, outputs)
      }
      _ => panic!("unexpeced event"),
    }
  };

  let mut scheduler = Scheduler::new(key);
  // Add these outputs, which should return no plans
  assert!(scheduler.add_outputs(outputs.clone()).is_empty());

  #[allow(clippy::inconsistent_digit_grouping)]
  let amount = 1_00_000_000;
  let plans = scheduler.schedule(vec![Payment { address: C::address(key), data: None, amount }]);
  assert_eq!(
    plans,
    vec![Plan {
      inputs: outputs,
      payments: vec![Payment { address: C::address(key), data: None, amount }],
      change: true,
    }]
  );

  // Execute the plan
  let fee = coin.get_fee().await;
  let mut keys_txs = HashMap::new();
  for (i, keys) in keys.drain() {
    keys_txs.insert(
      i,
      (
        keys.clone(),
        coin
          .prepare_send(
            keys,
            RecommendedTranscript::new(b"Processor Wallet Test"),
            sync_block,
            plans[0].clone(),
            key,
            fee,
          )
          .await
          .unwrap(),
      ),
    );
  }

  sign(coin.clone(), keys_txs).await;
  coin.mine_block().await;
  let block = coin.get_block(coin.get_latest_block_number().await.unwrap()).await.unwrap();
  let outputs = coin.get_outputs(&block, key).await.unwrap();
  assert_eq!(outputs.len(), 2);
  assert!((outputs[0].amount() == amount) || (outputs[1].amount() == amount));

  for _ in 1 .. C::CONFIRMATIONS {
    coin.mine_block().await;
  }

  // Check the Scanner also picks them up
  match timeout(Duration::from_secs(10), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Block(number, id) => {
      assert_eq!(coin.get_block(number).await.unwrap().id(), id);
      assert_eq!(id, block.id());
    }
    _ => panic!("unexpected event"),
  }

  match timeout(Duration::from_secs(1), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Outputs(this_key, block_id, these_outputs) => {
      assert_eq!(this_key, key);
      assert_eq!(block_id, block.id());
      assert_eq!(these_outputs, outputs);
    }
    _ => panic!("unexpeced event"),
  }

  // Check the Scanner DB can reload the outputs
  assert_eq!(scanner.outputs(key.to_bytes().as_ref(), &block.id()), outputs);
}
