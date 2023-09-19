use std::{time::Duration, collections::HashMap};

use rand_core::OsRng;

use frost::{Participant, dkg::tests::key_gen};

use tokio::time::timeout;

use serai_db::{DbTxn, Db, MemDb};

use crate::{
  Payment, Plan,
  networks::{Output, Transaction, Block, Network},
  multisigs::{
    scanner::{ScannerEvent, Scanner},
    scheduler::Scheduler,
  },
  tests::sign,
};

// Tests the Scanner, Scheduler, and Signer together
pub async fn test_wallet<N: Network>(network: N) {
  let mut keys = key_gen(&mut OsRng);
  for (_, keys) in keys.iter_mut() {
    N::tweak_keys(keys);
  }
  let key = keys[&Participant::new(1).unwrap()].group_key();

  let mut db = MemDb::new();
  let (mut scanner, active_keys) = Scanner::new(network.clone(), db.clone());
  assert!(active_keys.is_empty());
  let (block_id, outputs) = {
    let mut txn = db.txn();
    scanner.register_key(&mut txn, network.get_latest_block_number().await.unwrap(), key).await;
    txn.commit();

    let block = network.test_send(N::address(key)).await;
    let block_id = block.id();

    match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Block { block, outputs } => {
        assert_eq!(block, block_id);
        assert_eq!(outputs.len(), 1);
        (block_id, outputs)
      }
      ScannerEvent::Completed(_, _, _) => {
        panic!("unexpectedly got eventuality completion");
      }
    }
  };

  let mut txn = db.txn();
  let mut scheduler = Scheduler::new::<MemDb>(&mut txn, key);
  let amount = 2 * N::DUST;
  let plans = scheduler.schedule::<MemDb>(
    &mut txn,
    outputs.clone(),
    vec![Payment { address: N::address(key), data: None, amount }],
  );
  txn.commit();
  assert_eq!(
    plans,
    vec![Plan {
      key,
      inputs: outputs.clone(),
      payments: vec![Payment { address: N::address(key), data: None, amount }],
      change: Some(key),
    }]
  );

  {
    let mut buf = vec![];
    plans[0].write(&mut buf).unwrap();
    assert_eq!(plans[0], Plan::<N>::read::<&[u8]>(&mut buf.as_ref()).unwrap());
  }

  // Execute the plan
  let fee = network.get_fee().await;
  let mut keys_txs = HashMap::new();
  let mut eventualities = vec![];
  for (i, keys) in keys.drain() {
    let (signable, eventuality) = network
      .prepare_send(network.get_block_number(&block_id).await, plans[0].clone(), fee)
      .await
      .unwrap()
      .0
      .unwrap();

    eventualities.push(eventuality.clone());
    keys_txs.insert(i, (keys, (signable, eventuality)));
  }

  let first_block_id = block_id;
  let first_outputs = outputs;

  let txid = sign(network.clone(), keys_txs).await;
  let tx = network.get_transaction(&txid).await.unwrap();
  network.mine_block().await;
  let block_number = network.get_latest_block_number().await.unwrap();
  let block = network.get_block(block_number).await.unwrap();
  let outputs = network.get_outputs(&block, key).await;
  assert_eq!(outputs.len(), 2);
  let amount = amount - tx.fee(&network).await;
  assert!((outputs[0].amount() == amount) || (outputs[1].amount() == amount));

  for eventuality in eventualities {
    assert!(network.confirm_completion(&eventuality, &tx));
  }

  for _ in 1 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }

  match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Block { block: block_id, outputs: these_outputs } => {
      assert_eq!(block_id, block.id());
      assert_eq!(these_outputs, outputs);
    }
    ScannerEvent::Completed(_, _, _) => {
      panic!("unexpectedly got eventuality completion");
    }
  }

  // Check the Scanner DB can reload the outputs
  let mut txn = db.txn();
  assert_eq!(scanner.ack_block(&mut txn, first_block_id).await, first_outputs);
  assert_eq!(scanner.ack_block(&mut txn, block.id()).await, outputs);
  txn.commit();
}
