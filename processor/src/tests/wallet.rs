use std::{time::Duration, collections::HashMap};

use rand_core::OsRng;

use frost::{Participant, dkg::tests::key_gen};

use tokio::time::timeout;

use crate::{
  Payment, Plan,
  coins::{Output, Transaction, Block, Coin},
  scanner::{ScannerEvent, Scanner},
  scheduler::Scheduler,
  tests::{util::db::MemDb, sign},
};

// Tests the Scanner, Scheduler, and Signer together
pub async fn test_wallet<C: Coin>(coin: C) {
  let mut keys = key_gen(&mut OsRng);
  for (_, keys) in keys.iter_mut() {
    C::tweak_keys(keys);
  }
  let key = keys[&Participant::new(1).unwrap()].group_key();

  let (mut scanner, active_keys) = Scanner::new(coin.clone(), MemDb::new());
  assert!(active_keys.is_empty());
  let (block_id, outputs) = {
    scanner.rotate_key(coin.get_latest_block_number().await.unwrap(), key).await;

    let block_id = coin.test_send(C::address(key)).await.id();

    match timeout(Duration::from_secs(10), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Outputs(this_key, block, outputs) => {
        assert_eq!(this_key, key);
        assert_eq!(block, block_id);
        assert_eq!(outputs.len(), 1);
        (block_id, outputs)
      }
    }
  };

  let mut scheduler = Scheduler::new(key);
  // Add these outputs, which should return no plans
  assert!(scheduler.add_outputs(outputs.clone()).is_empty());

  let amount = 2 * C::DUST;
  let plans = scheduler.schedule(vec![Payment { address: C::address(key), data: None, amount }]);
  assert_eq!(
    plans,
    vec![Plan {
      key,
      inputs: outputs,
      payments: vec![Payment { address: C::address(key), data: None, amount }],
      change: Some(key),
    }]
  );

  {
    let mut buf = vec![];
    plans[0].write(&mut buf).unwrap();
    assert_eq!(plans[0], Plan::<C>::read::<&[u8]>(&mut buf.as_ref()).unwrap());
  }

  // Execute the plan
  let fee = coin.get_fee().await;
  let mut keys_txs = HashMap::new();
  let mut eventualities = vec![];
  for (i, keys) in keys.drain() {
    let (signable, eventuality) = coin
      .prepare_send(keys.clone(), coin.get_block_number(&block_id).await, plans[0].clone(), fee)
      .await
      .unwrap()
      .0
      .unwrap();

    eventualities.push(eventuality.clone());
    keys_txs.insert(i, (keys, (signable, eventuality)));
  }

  let txid = sign(coin.clone(), keys_txs).await;
  let tx = coin.get_transaction(&txid).await.unwrap();
  coin.mine_block().await;
  let block_number = coin.get_latest_block_number().await.unwrap();
  let block = coin.get_block(block_number).await.unwrap();
  let outputs = coin.get_outputs(&block, key).await.unwrap();
  assert_eq!(outputs.len(), 2);
  let amount = amount - tx.fee(&coin).await;
  assert!((outputs[0].amount() == amount) || (outputs[1].amount() == amount));

  for eventuality in eventualities {
    assert!(coin.confirm_completion(&eventuality, &tx));
  }

  for _ in 1 .. C::CONFIRMATIONS {
    coin.mine_block().await;
  }

  match timeout(Duration::from_secs(10), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Outputs(this_key, block_id, these_outputs) => {
      assert_eq!(this_key, key);
      assert_eq!(block_id, block.id());
      assert_eq!(these_outputs, outputs);
    }
  }

  // Check the Scanner DB can reload the outputs
  assert_eq!(scanner.ack_block(key, block.id()).await, outputs);
}
