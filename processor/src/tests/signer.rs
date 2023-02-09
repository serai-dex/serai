use std::{
  time::{Duration, SystemTime},
  collections::HashMap,
};

use rand_core::OsRng;

use group::GroupEncoding;
use frost::{
  ThresholdKeys,
  dkg::tests::{key_gen, clone_without},
};

use tokio::time::timeout;

use messages::sign::*;
use crate::{
  Payment, Plan,
  coin::{Output, Transaction, Coin},
  signer::{SignerOrder, SignerEvent, Signer},
  tests::util::db::MemDb,
};

pub async fn sign<C: Coin>(
  coin: C,
  mut keys_txs: HashMap<u16, (ThresholdKeys<C::Curve>, C::SignableTransaction)>,
) -> <C::Transaction as Transaction>::Id {
  let actual_id = SignId {
    key: keys_txs[&1].0.group_key().to_bytes().as_ref().to_vec(),
    id: [0xaa; 32],
    attempt: 0,
  };

  let signing_set = actual_id.signing_set(&keys_txs[&1].0.params());
  let mut keys = HashMap::new();
  let mut txs = HashMap::new();
  for (i, (these_keys, this_tx)) in keys_txs.drain() {
    assert_eq!(actual_id.signing_set(&these_keys.params()), signing_set);
    keys.insert(i, these_keys);
    txs.insert(i, this_tx);
  }

  let mut signers = HashMap::new();
  for i in 1 ..= keys.len() {
    let i = u16::try_from(i).unwrap();
    signers.insert(i, Signer::new(MemDb::new(), coin.clone(), keys.remove(&i).unwrap()));
  }

  let start = SystemTime::now();
  for i in 1 ..= signers.len() {
    let i = u16::try_from(i).unwrap();
    signers[&i]
      .orders
      .send(SignerOrder::SignTransaction { id: actual_id.id, start, tx: txs.remove(&i).unwrap() })
      .unwrap();
  }

  let mut preprocesses = HashMap::new();
  for i in &signing_set {
    if let Some(SignerEvent::ProcessorMessage(ProcessorMessage::Preprocess { id, preprocess })) =
      signers.get_mut(i).unwrap().events.recv().await
    {
      assert_eq!(id, actual_id);
      preprocesses.insert(*i, preprocess);
    } else {
      panic!("didn't get preprocess back");
    }
  }

  let mut shares = HashMap::new();
  for i in &signing_set {
    signers[i]
      .orders
      .send(SignerOrder::CoordinatorMessage(CoordinatorMessage::Preprocesses {
        id: actual_id.clone(),
        preprocesses: clone_without(&preprocesses, i),
      }))
      .unwrap();
    if let Some(SignerEvent::ProcessorMessage(ProcessorMessage::Share { id, share })) =
      signers.get_mut(i).unwrap().events.recv().await
    {
      assert_eq!(id, actual_id);
      shares.insert(*i, share);
    } else {
      panic!("didn't get share back");
    }
  }

  let mut tx_id = None;
  for i in &signing_set {
    signers[i]
      .orders
      .send(SignerOrder::CoordinatorMessage(CoordinatorMessage::Shares {
        id: actual_id.clone(),
        shares: clone_without(&shares, i),
      }))
      .unwrap();
    if let Some(SignerEvent::SignedTransaction { id, tx }) =
      signers.get_mut(i).unwrap().events.recv().await
    {
      assert_eq!(id, actual_id.id);
      if tx_id.is_none() {
        tx_id = Some(tx.clone());
      }
      assert_eq!(tx_id, Some(tx));
    } else {
      panic!("didn't get TX back");
    }
  }

  // Make sure the signers not included didn't do anything
  let mut excluded = (1 ..= signers.len()).collect::<Vec<_>>();
  for i in signing_set {
    excluded.remove(excluded.binary_search(&usize::from(i)).unwrap());
  }
  for i in excluded {
    assert!(timeout(
      Duration::from_secs(1),
      signers.get_mut(&u16::try_from(i).unwrap()).unwrap().events.recv()
    )
    .await
    .is_err());
  }

  tx_id.unwrap()
}

pub async fn test_signer<C: Coin>(coin: C) {
  let mut keys = key_gen(&mut OsRng);
  for (_, keys) in keys.iter_mut() {
    C::tweak_keys(keys);
  }
  let key = keys[&1].group_key();

  let outputs = coin.get_outputs(&coin.test_send(C::address(key)).await, key).await.unwrap();
  let sync_block = coin.get_latest_block_number().await.unwrap() - C::CONFIRMATIONS;
  let fee = coin.get_fee().await;

  #[allow(clippy::inconsistent_digit_grouping)]
  let amount = 1_00_000_000;
  let mut keys_txs = HashMap::new();
  for (i, keys) in keys.drain() {
    keys_txs.insert(
      i,
      (
        keys.clone(),
        coin
          .prepare_send(
            keys,
            sync_block,
            Plan {
              key,
              inputs: outputs.clone(),
              payments: vec![Payment { address: C::address(key), data: None, amount }],
              change: true,
            },
            key,
            fee,
          )
          .await
          .unwrap(),
      ),
    );
  }

  // The signer may not publish the TX if it has a connection error
  // It doesn't fail in this case
  sign(coin.clone(), keys_txs).await;
  // Mine a block, and scan it, to ensure that the TX actually made it on chain
  coin.mine_block().await;
  let outputs = coin
    .get_outputs(&coin.get_block(coin.get_latest_block_number().await.unwrap()).await.unwrap(), key)
    .await
    .unwrap();
  assert_eq!(outputs.len(), 2);
  // Check either output since Monero will randomize its output order
  assert!((outputs[0].amount() == amount) || (outputs[1].amount() == amount));
}
