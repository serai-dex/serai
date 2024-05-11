use core::{pin::Pin, future::Future};
use std::collections::HashMap;

use rand_core::{RngCore, OsRng};

use ciphersuite::group::GroupEncoding;
use frost::{
  Participant, ThresholdKeys,
  dkg::tests::{key_gen, clone_without},
};

use serai_db::{DbTxn, Db, MemDb};

use serai_client::{
  primitives::{NetworkId, Coin, Amount, Balance},
  validator_sets::primitives::Session,
};

use messages::sign::*;
use crate::{
  Payment,
  networks::{Output, Transaction, Eventuality, Network},
  key_gen::NetworkKeyDb,
  multisigs::scheduler::Scheduler,
  signer::Signer,
};

#[allow(clippy::type_complexity)]
pub async fn sign<N: Network>(
  network: N,
  session: Session,
  mut keys_txs: HashMap<
    Participant,
    (ThresholdKeys<N::Curve>, (N::SignableTransaction, N::Eventuality)),
  >,
) -> <N::Eventuality as Eventuality>::Claim {
  let actual_id = SignId { session, id: [0xaa; 32], attempt: 0 };

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
    signers.insert(i, Signer::<_, MemDb>::new(network.clone(), Session(0), vec![keys]));
    dbs.insert(i, MemDb::new());
  }
  drop(keys);

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

  let mut preprocesses = HashMap::new();

  let mut eventuality = None;
  for i in 1 ..= signers.len() {
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    let (tx, this_eventuality) = txs.remove(&i).unwrap();
    let mut txn = dbs.get_mut(&i).unwrap().txn();
    match signers
      .get_mut(&i)
      .unwrap()
      .sign_transaction(&mut txn, actual_id.id, tx, &this_eventuality)
      .await
    {
      // All participants should emit a preprocess
      Some(ProcessorMessage::Preprocess { id, preprocesses: mut these_preprocesses }) => {
        assert_eq!(id, actual_id);
        assert_eq!(these_preprocesses.len(), 1);
        if signing_set.contains(&i) {
          preprocesses.insert(i, these_preprocesses.swap_remove(0));
        }
      }
      _ => panic!("didn't get preprocess back"),
    }
    txn.commit();

    if eventuality.is_none() {
      eventuality = Some(this_eventuality.clone());
    }
    assert_eq!(eventuality, Some(this_eventuality));
  }

  let mut shares = HashMap::new();
  for i in &signing_set {
    let mut txn = dbs.get_mut(i).unwrap().txn();
    match signers
      .get_mut(i)
      .unwrap()
      .handle(
        &mut txn,
        CoordinatorMessage::Preprocesses {
          id: actual_id.clone(),
          preprocesses: clone_without(&preprocesses, i),
        },
      )
      .await
      .unwrap()
    {
      ProcessorMessage::Share { id, shares: mut these_shares } => {
        assert_eq!(id, actual_id);
        assert_eq!(these_shares.len(), 1);
        shares.insert(*i, these_shares.swap_remove(0));
      }
      _ => panic!("didn't get share back"),
    }
    txn.commit();
  }

  let mut tx_id = None;
  for i in &signing_set {
    let mut txn = dbs.get_mut(i).unwrap().txn();
    match signers
      .get_mut(i)
      .unwrap()
      .handle(
        &mut txn,
        CoordinatorMessage::Shares { id: actual_id.clone(), shares: clone_without(&shares, i) },
      )
      .await
      .unwrap()
    {
      ProcessorMessage::Completed { session, id, tx } => {
        assert_eq!(session, Session(0));
        assert_eq!(id, actual_id.id);
        if tx_id.is_none() {
          tx_id = Some(tx.clone());
        }
        assert_eq!(tx_id, Some(tx));
      }
      _ => panic!("didn't get TX back"),
    }
    txn.commit();
  }

  let mut typed_claim = <N::Eventuality as Eventuality>::Claim::default();
  typed_claim.as_mut().copy_from_slice(tx_id.unwrap().as_ref());
  assert!(network.check_eventuality_by_claim(&eventuality.unwrap(), &typed_claim).await);
  typed_claim
}

pub async fn test_signer<N: Network>(
  new_network: impl Fn(MemDb) -> Pin<Box<dyn Send + Future<Output = N>>>,
) {
  let mut keys = key_gen(&mut OsRng);
  for keys in keys.values_mut() {
    N::tweak_keys(keys);
  }
  let key = keys[&Participant::new(1).unwrap()].group_key();

  let mut db = MemDb::new();
  {
    let mut txn = db.txn();
    NetworkKeyDb::set(&mut txn, Session(0), &key.to_bytes().as_ref().to_vec());
    txn.commit();
  }
  let network = new_network(db.clone()).await;

  let outputs = network
    .get_outputs(&network.test_send(N::external_address(&network, key).await).await, key)
    .await;
  let sync_block = network.get_latest_block_number().await.unwrap() - N::CONFIRMATIONS;

  let amount = (2 * N::DUST) + 1000;
  let plan = {
    let mut txn = db.txn();
    let mut scheduler = N::Scheduler::new::<MemDb>(&mut txn, key, N::NETWORK);
    let payments = vec![Payment {
      address: N::external_address(&network, key).await,
      data: None,
      balance: Balance {
        coin: match N::NETWORK {
          NetworkId::Serai => panic!("test_signer called with Serai"),
          NetworkId::Bitcoin => Coin::Bitcoin,
          NetworkId::Ethereum => Coin::Ether,
          NetworkId::Monero => Coin::Monero,
        },
        amount: Amount(amount),
      },
    }];
    let mut plans = scheduler.schedule::<MemDb>(&mut txn, outputs.clone(), payments, key, false);
    assert_eq!(plans.len(), 1);
    plans.swap_remove(0)
  };

  let mut keys_txs = HashMap::new();
  let mut eventualities = vec![];
  for (i, keys) in keys.drain() {
    let (signable, eventuality) =
      network.prepare_send(sync_block, plan.clone(), 0).await.unwrap().tx.unwrap();

    eventualities.push(eventuality.clone());
    keys_txs.insert(i, (keys, (signable, eventuality)));
  }

  let claim = sign(network.clone(), Session(0), keys_txs).await;

  // Mine a block, and scan it, to ensure that the TX actually made it on chain
  network.mine_block().await;
  let block_number = network.get_latest_block_number().await.unwrap();
  let tx = network.get_transaction_by_eventuality(block_number, &eventualities[0]).await;
  let outputs = network
    .get_outputs(
      &network.get_block(network.get_latest_block_number().await.unwrap()).await.unwrap(),
      key,
    )
    .await;
  // Don't run if Ethereum as the received output will revert by the contract
  // (and therefore not actually exist)
  if N::NETWORK != NetworkId::Ethereum {
    assert_eq!(outputs.len(), 1 + usize::from(u8::from(plan.change.is_some())));
    // Adjust the amount for the fees
    let amount = amount - tx.fee(&network).await;
    if plan.change.is_some() {
      // Check either output since Monero will randomize its output order
      assert!(
        (outputs[0].balance().amount.0 == amount) || (outputs[1].balance().amount.0 == amount)
      );
    } else {
      assert!(outputs[0].balance().amount.0 == amount);
    }
  }

  // Check the eventualities pass
  for eventuality in eventualities {
    let completion = network.confirm_completion(&eventuality, &claim).await.unwrap().unwrap();
    assert_eq!(N::Eventuality::claim(&completion), claim);
  }
}
