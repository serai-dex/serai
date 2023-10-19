use std::collections::HashMap;

use rand_core::{RngCore, OsRng};

use ciphersuite::group::GroupEncoding;
use frost::{
  Participant, ThresholdKeys,
  dkg::tests::{key_gen, clone_without},
};

use serai_db::{DbTxn, Db, MemDb};

use messages::sign::*;
use crate::{
  Payment, Plan,
  networks::{Output, Transaction, Network},
  signer::{SignerEvent, Signer},
};

#[allow(clippy::type_complexity)]
pub async fn sign<N: Network>(
  network: N,
  mut keys_txs: HashMap<
    Participant,
    (ThresholdKeys<N::Curve>, (N::SignableTransaction, N::Eventuality)),
  >,
) -> <N::Transaction as Transaction<N>>::Id {
  let actual_id = SignId {
    key: keys_txs[&Participant::new(1).unwrap()].0.group_key().to_bytes().as_ref().to_vec(),
    id: [0xaa; 32],
    attempt: 0,
  };

  let mut keys = HashMap::new();
  let mut txs = HashMap::new();
  for (i, (these_keys, this_tx)) in keys_txs.drain() {
    keys.insert(i, these_keys);
    txs.insert(i, this_tx);
  }

  let mut signers = HashMap::new();
  let mut dbs = HashMap::new();
  let mut t = 0;
  for i in 1 ..= keys.len() {
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    let keys = keys.remove(&i).unwrap();
    t = keys.params().t();
    signers.insert(i, Signer::<_, MemDb>::new(network.clone(), keys));
    dbs.insert(i, MemDb::new());
  }
  drop(keys);

  for i in 1 ..= signers.len() {
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    let (tx, eventuality) = txs.remove(&i).unwrap();
    let mut txn = dbs.get_mut(&i).unwrap().txn();
    signers.get_mut(&i).unwrap().sign_transaction(&mut txn, actual_id.id, tx, eventuality).await;
    txn.commit();
  }

  let mut signing_set = vec![];
  while signing_set.len() < usize::from(t) {
    let candidate = Participant::new(
      u16::try_from((OsRng.next_u64() % u64::try_from(signers.len()).unwrap()) + 1).unwrap(),
    )
    .unwrap();
    if signing_set.contains(&candidate) {
      continue;
    }
    signing_set.push(candidate);
  }

  // All participants should emit a preprocess
  let mut preprocesses = HashMap::new();
  for i in 1 ..= signers.len() {
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    if let SignerEvent::ProcessorMessage(ProcessorMessage::Preprocess { id, preprocess }) =
      signers.get_mut(&i).unwrap().events.pop_front().unwrap()
    {
      assert_eq!(id, actual_id);
      if signing_set.contains(&i) {
        preprocesses.insert(i, preprocess);
      }
    } else {
      panic!("didn't get preprocess back");
    }
  }

  let mut shares = HashMap::new();
  for i in &signing_set {
    let mut txn = dbs.get_mut(i).unwrap().txn();
    signers
      .get_mut(i)
      .unwrap()
      .handle(
        &mut txn,
        CoordinatorMessage::Preprocesses {
          id: actual_id.clone(),
          preprocesses: clone_without(&preprocesses, i),
        },
      )
      .await;
    txn.commit();

    if let SignerEvent::ProcessorMessage(ProcessorMessage::Share { id, share }) =
      signers.get_mut(i).unwrap().events.pop_front().unwrap()
    {
      assert_eq!(id, actual_id);
      shares.insert(*i, share);
    } else {
      panic!("didn't get share back");
    }
  }

  let mut tx_id = None;
  for i in &signing_set {
    let mut txn = dbs.get_mut(i).unwrap().txn();
    signers
      .get_mut(i)
      .unwrap()
      .handle(
        &mut txn,
        CoordinatorMessage::Shares { id: actual_id.clone(), shares: clone_without(&shares, i) },
      )
      .await;
    txn.commit();

    if let SignerEvent::SignedTransaction { id, tx } =
      signers.get_mut(i).unwrap().events.pop_front().unwrap()
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

  // Make sure there's no events left
  for (_, mut signer) in signers.drain() {
    assert!(signer.events.pop_front().is_none());
  }

  tx_id.unwrap()
}

pub async fn test_signer<N: Network>(network: N) {
  let mut keys = key_gen(&mut OsRng);
  for (_, keys) in keys.iter_mut() {
    N::tweak_keys(keys);
  }
  let key = keys[&Participant::new(1).unwrap()].group_key();

  let outputs = network.get_outputs(&network.test_send(N::address(key)).await, key).await;
  let sync_block = network.get_latest_block_number().await.unwrap() - N::CONFIRMATIONS;
  let fee = network.get_fee().await;

  let amount = 2 * N::DUST;
  let mut keys_txs = HashMap::new();
  let mut eventualities = vec![];
  for (i, keys) in keys.drain() {
    let (signable, eventuality) = network
      .prepare_send(
        sync_block,
        Plan {
          key,
          inputs: outputs.clone(),
          payments: vec![Payment { address: N::address(key), data: None, amount }],
          change: Some(N::change_address(key)),
        },
        fee,
        0,
      )
      .await
      .unwrap()
      .tx
      .unwrap();

    eventualities.push(eventuality.clone());
    keys_txs.insert(i, (keys, (signable, eventuality)));
  }

  // The signer may not publish the TX if it has a connection error
  // It doesn't fail in this case
  let txid = sign(network.clone(), keys_txs).await;
  let tx = network.get_transaction(&txid).await.unwrap();
  assert_eq!(tx.id(), txid);
  // Mine a block, and scan it, to ensure that the TX actually made it on chain
  network.mine_block().await;
  let outputs = network
    .get_outputs(
      &network.get_block(network.get_latest_block_number().await.unwrap()).await.unwrap(),
      key,
    )
    .await;
  assert_eq!(outputs.len(), 2);
  // Adjust the amount for the fees
  let amount = amount - tx.fee(&network).await;
  // Check either output since Monero will randomize its output order
  assert!((outputs[0].amount() == amount) || (outputs[1].amount() == amount));

  // Check the eventualities pass
  for eventuality in eventualities {
    assert!(network.confirm_completion(&eventuality, &tx));
  }
}
