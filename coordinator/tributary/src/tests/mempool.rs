use std::{sync::Arc, collections::HashMap};

use zeroize::Zeroizing;
use rand::{RngCore, rngs::OsRng};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use tendermint::ext::Commit;

use serai_db::MemDb;

use crate::{
  transaction::{TransactionError, Transaction as TransactionTrait},
  tendermint::{TendermintBlock, Validators, Signer, TendermintNetwork},
  ACCOUNT_MEMPOOL_LIMIT, Transaction, Mempool,
  tests::{SignedTransaction, signed_transaction, p2p::DummyP2p, random_evidence_tx},
};

type N = TendermintNetwork<MemDb, SignedTransaction, DummyP2p>;

fn new_mempool<T: TransactionTrait>() -> ([u8; 32], MemDb, Mempool<MemDb, T>) {
  let mut genesis = [0; 32];
  OsRng.fill_bytes(&mut genesis);
  let db = MemDb::new();
  (genesis, db.clone(), Mempool::new(db, genesis))
}

#[tokio::test]
async fn mempool_addition() {
  let (genesis, db, mut mempool) = new_mempool::<SignedTransaction>();
  let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
    Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
  };
  let unsigned_in_chain = |_: [u8; 32]| false;
  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));

  let first_tx = signed_transaction(&mut OsRng, genesis, &key, 0);
  let signer = first_tx.1.signer;
  assert_eq!(mempool.next_nonce_in_mempool(&signer, vec![]), None);

  // validators
  let validators = Arc::new(Validators::new(genesis, vec![(signer, 1)]).unwrap());

  // Add TX 0
  assert!(mempool
    .add::<N, _>(
      &|_, _| Some(0),
      true,
      Transaction::Application(first_tx.clone()),
      &validators,
      unsigned_in_chain,
      commit,
    )
    .unwrap());
  assert_eq!(mempool.next_nonce_in_mempool(&signer, vec![]), Some(1));

  // add a tendermint evidence tx
  let evidence_tx =
    random_evidence_tx::<N>(Signer::new(genesis, key.clone()).into(), TendermintBlock(vec![]))
      .await;
  assert!(mempool
    .add::<N, _>(
      &|_, _| None,
      true,
      Transaction::Tendermint(evidence_tx.clone()),
      &validators,
      unsigned_in_chain,
      commit,
    )
    .unwrap());

  // Test reloading works
  assert_eq!(mempool, Mempool::new(db, genesis));

  // Adding them again should fail
  assert_eq!(
    mempool.add::<N, _>(
      &|_, _| Some(0),
      true,
      Transaction::Application(first_tx.clone()),
      &validators,
      unsigned_in_chain,
      commit,
    ),
    Err(TransactionError::InvalidNonce)
  );
  assert_eq!(
    mempool.add::<N, _>(
      &|_, _| None,
      true,
      Transaction::Tendermint(evidence_tx.clone()),
      &validators,
      unsigned_in_chain,
      commit,
    ),
    Ok(false)
  );

  // Do the same with the next nonce
  let second_tx = signed_transaction(&mut OsRng, genesis, &key, 1);
  assert_eq!(
    mempool.add::<N, _>(
      &|_, _| Some(0),
      true,
      Transaction::Application(second_tx.clone()),
      &validators,
      unsigned_in_chain,
      commit,
    ),
    Ok(true)
  );
  assert_eq!(mempool.next_nonce_in_mempool(&signer, vec![]), Some(2));
  assert_eq!(
    mempool.add::<N, _>(
      &|_, _| Some(0),
      true,
      Transaction::Application(second_tx.clone()),
      &validators,
      unsigned_in_chain,
      commit,
    ),
    Err(TransactionError::InvalidNonce)
  );

  // If the mempool doesn't have a nonce for an account, it should successfully use the
  // blockchain's
  let second_key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let tx = signed_transaction(&mut OsRng, genesis, &second_key, 2);
  let second_signer = tx.1.signer;
  assert_eq!(mempool.next_nonce_in_mempool(&second_signer, vec![]), None);
  assert!(mempool
    .add::<N, _>(
      &|_, _| Some(2),
      true,
      Transaction::Application(tx.clone()),
      &validators,
      unsigned_in_chain,
      commit
    )
    .unwrap());
  assert_eq!(mempool.next_nonce_in_mempool(&second_signer, vec![]), Some(3));

  // Getting a block should work
  assert_eq!(mempool.block().len(), 4);

  // Removing should successfully prune
  mempool.remove(&tx.hash());

  assert_eq!(
    mempool.txs(),
    &HashMap::from([
      (first_tx.hash(), Transaction::Application(first_tx)),
      (second_tx.hash(), Transaction::Application(second_tx)),
      (evidence_tx.hash(), Transaction::Tendermint(evidence_tx))
    ])
  );
}

#[test]
fn too_many_mempool() {
  let (genesis, _, mut mempool) = new_mempool::<SignedTransaction>();
  let validators = Arc::new(Validators::new(genesis, vec![]).unwrap());
  let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
    Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
  };
  let unsigned_in_chain = |_: [u8; 32]| false;
  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));

  // We should be able to add transactions up to the limit
  for i in 0 .. ACCOUNT_MEMPOOL_LIMIT {
    assert!(mempool
      .add::<N, _>(
        &|_, _| Some(0),
        false,
        Transaction::Application(signed_transaction(&mut OsRng, genesis, &key, i)),
        &validators,
        unsigned_in_chain,
        commit,
      )
      .unwrap());
  }
  // Yet adding more should fail
  assert_eq!(
    mempool.add::<N, _>(
      &|_, _| Some(0),
      false,
      Transaction::Application(signed_transaction(
        &mut OsRng,
        genesis,
        &key,
        ACCOUNT_MEMPOOL_LIMIT
      )),
      &validators,
      unsigned_in_chain,
      commit,
    ),
    Err(TransactionError::TooManyInMempool)
  );
}
