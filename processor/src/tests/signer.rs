use std::{
  time::{Duration, SystemTime},
  collections::HashMap,
};

use rand_core::OsRng;

use transcript::{Transcript, RecommendedTranscript};
use frost::{
  ThresholdParams,
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

const ID: SignId = SignId { id: [0xaa; 32], attempt: 0 };

pub async fn sign<C: Coin>(
  coin: C,
  mut params_txs: HashMap<u16, (ThresholdParams, C::SignableTransaction)>,
) -> <C::Transaction as Transaction>::Id {
  let signing_set = ID.signing_set(&params_txs[&1].0);
  let mut params = HashMap::new();
  let mut txs = HashMap::new();
  for (i, (these_params, this_tx)) in params_txs.drain() {
    assert_eq!(ID.signing_set(&these_params), signing_set);
    params.insert(i, these_params);
    txs.insert(i, this_tx);
  }

  let mut signers = HashMap::new();
  for i in 1 ..= params.len() {
    let i = u16::try_from(i).unwrap();
    signers.insert(i, Signer::new(MemDb::new(), coin.clone(), params.remove(&i).unwrap()));
  }

  let start = SystemTime::now();
  for i in 1 ..= signers.len() {
    let i = u16::try_from(i).unwrap();
    signers[&i]
      .orders
      .send(SignerOrder::SignTransaction { id: ID.id, start, tx: txs.remove(&i).unwrap() })
      .unwrap();
  }

  let mut preprocesses = HashMap::new();
  for i in &signing_set {
    if let Some(SignerEvent::ProcessorMessage(ProcessorMessage::Preprocess { id, preprocess })) =
      signers.get_mut(i).unwrap().events.recv().await
    {
      assert_eq!(id, ID);
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
        id: ID,
        preprocesses: clone_without(&preprocesses, i),
      }))
      .unwrap();
    if let Some(SignerEvent::ProcessorMessage(ProcessorMessage::Share { id, share })) =
      signers.get_mut(i).unwrap().events.recv().await
    {
      assert_eq!(id, ID);
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
        id: ID,
        shares: clone_without(&shares, i),
      }))
      .unwrap();
    if let Some(SignerEvent::SignedTransaction { id, tx }) =
      signers.get_mut(i).unwrap().events.recv().await
    {
      assert_eq!(id, ID.id);
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
  let mut params_txs = HashMap::new();
  for (i, keys) in keys.drain() {
    params_txs.insert(
      i,
      (
        keys.params(),
        coin
          .prepare_send(
            keys,
            RecommendedTranscript::new(b"Processor Signer Test"),
            sync_block,
            Plan {
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
  sign(coin.clone(), params_txs).await;
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
