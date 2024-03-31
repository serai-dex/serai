use std::{time::Duration, collections::HashMap};

use rand_core::OsRng;

use frost::{Participant, dkg::tests::key_gen};

use tokio::time::timeout;

use serai_db::{DbTxn, Db, MemDb};

use serai_client::{
  primitives::{NetworkId, Coin, Amount, Balance},
  validator_sets::primitives::Session,
};

use crate::{
  Payment, Plan,
  networks::{Output, Transaction, Eventuality, Block, Network},
  multisigs::{
    scanner::{ScannerEvent, Scanner},
    scheduler::Scheduler,
  },
  tests::sign,
};

// Tests the Scanner, Scheduler, and Signer together
pub async fn test_wallet<N: Network>(network: N) {
  // Mine blocks so there's a confirmed block
  for _ in 0 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }

  let mut keys = key_gen(&mut OsRng);
  for keys in keys.values_mut() {
    N::tweak_keys(keys);
  }
  let key = keys[&Participant::new(1).unwrap()].group_key();

  let mut db = MemDb::new();
  let (mut scanner, current_keys) = Scanner::new(network.clone(), db.clone());
  assert!(current_keys.is_empty());
  let (block_id, outputs) = {
    let mut txn = db.txn();
    scanner.register_key(&mut txn, network.get_latest_block_number().await.unwrap(), key).await;
    txn.commit();
    for _ in 0 .. N::CONFIRMATIONS {
      network.mine_block().await;
    }

    let block = network.test_send(N::external_address(key)).await;
    let block_id = block.id();

    match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
      ScannerEvent::Block { is_retirement_block, block, outputs } => {
        scanner.multisig_completed.send(false).unwrap();
        assert!(!is_retirement_block);
        assert_eq!(block, block_id);
        assert_eq!(outputs.len(), 1);
        (block_id, outputs)
      }
      ScannerEvent::Completed(_, _, _, _, _) => {
        panic!("unexpectedly got eventuality completion");
      }
    }
  };
  let mut txn = db.txn();
  assert_eq!(scanner.ack_block(&mut txn, block_id.clone()).await.1, outputs);
  scanner.release_lock().await;
  txn.commit();

  let mut txn = db.txn();
  let mut scheduler = N::Scheduler::new::<MemDb>(&mut txn, key, N::NETWORK);
  let amount = 2 * N::DUST;
  let plans = scheduler.schedule::<MemDb>(
    &mut txn,
    outputs.clone(),
    vec![Payment {
      address: N::external_address(key),
      data: None,
      balance: Balance {
        coin: match N::NETWORK {
          NetworkId::Serai => panic!("test_wallet called with Serai"),
          NetworkId::Bitcoin => Coin::Bitcoin,
          NetworkId::Ethereum => Coin::Ether,
          NetworkId::Monero => Coin::Monero,
        },
        amount: Amount(amount),
      },
    }],
    key,
    false,
  );
  txn.commit();
  assert_eq!(
    plans,
    vec![Plan {
      key,
      inputs: outputs.clone(),
      payments: vec![Payment {
        address: N::external_address(key),
        data: None,
        balance: Balance {
          coin: match N::NETWORK {
            NetworkId::Serai => panic!("test_wallet called with Serai"),
            NetworkId::Bitcoin => Coin::Bitcoin,
            NetworkId::Ethereum => Coin::Ether,
            NetworkId::Monero => Coin::Monero,
          },
          amount: Amount(amount),
        }
      }],
      change: Some(N::change_address(key)),
    }]
  );

  {
    let mut buf = vec![];
    plans[0].write(&mut buf).unwrap();
    assert_eq!(plans[0], Plan::<N>::read::<&[u8]>(&mut buf.as_ref()).unwrap());
  }

  // Execute the plan
  let mut keys_txs = HashMap::new();
  let mut eventualities = vec![];
  for (i, keys) in keys.drain() {
    let (signable, eventuality) = network
      .prepare_send(network.get_block_number(&block_id).await, plans[0].clone(), 0)
      .await
      .unwrap()
      .tx
      .unwrap();

    eventualities.push(eventuality.clone());
    keys_txs.insert(i, (keys, (signable, eventuality)));
  }

  let claim = sign(network.clone(), Session(0), keys_txs).await;
  network.mine_block().await;
  let block_number = network.get_latest_block_number().await.unwrap();
  let tx = network.get_transaction_by_eventuality(block_number, &eventualities[0]).await;
  let block = network.get_block(block_number).await.unwrap();
  let outputs = network.get_outputs(&block, key).await;
  assert_eq!(outputs.len(), 2);
  let amount = amount - tx.fee(&network).await;
  assert!((outputs[0].balance().amount.0 == amount) || (outputs[1].balance().amount.0 == amount));

  for eventuality in eventualities {
    let completion = network.confirm_completion(&eventuality, &claim).await.unwrap().unwrap();
    assert_eq!(N::Eventuality::claim(&completion), claim);
  }

  for _ in 1 .. N::CONFIRMATIONS {
    network.mine_block().await;
  }

  match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Block { is_retirement_block, block: block_id, outputs: these_outputs } => {
      scanner.multisig_completed.send(false).unwrap();
      assert!(!is_retirement_block);
      assert_eq!(block_id, block.id());
      assert_eq!(these_outputs, outputs);
    }
    ScannerEvent::Completed(_, _, _, _, _) => {
      panic!("unexpectedly got eventuality completion");
    }
  }

  // Check the Scanner DB can reload the outputs
  let mut txn = db.txn();
  assert_eq!(scanner.ack_block(&mut txn, block.id()).await.1, outputs);
  scanner.release_lock().await;
  txn.commit();
}
