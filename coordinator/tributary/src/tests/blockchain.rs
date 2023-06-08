use std::{collections::{VecDeque, HashMap}, sync::Arc};

use zeroize::Zeroizing;
use rand::{RngCore, rngs::OsRng};

use blake2::{Digest, Blake2s256};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use serai_db::{DbTxn, Db, MemDb};

use crate::{
  transaction::Transaction as TransactionTrait,
  merkle, ProvidedError, ProvidedTransactions, Block, Blockchain, Transaction,
  tests::{ProvidedTransaction, SignedTransaction, random_provided_transaction, p2p::LocalP2p}, tendermint::{TendermintNetwork, Validators},
};

type N = TendermintNetwork<MemDb, SignedTransaction, LocalP2p>;

fn new_genesis() -> [u8; 32] {
  let mut genesis = [0; 32];
  OsRng.fill_bytes(&mut genesis);
  genesis
}

fn new_blockchain<T: TransactionTrait>(
  genesis: [u8; 32],
  participants: &[<Ristretto as Ciphersuite>::G],
) -> (MemDb, Blockchain<MemDb, T>) {
  let db = MemDb::new();
  let blockchain = Blockchain::new(db.clone(), genesis, participants);
  assert_eq!(blockchain.tip(), genesis);
  assert_eq!(blockchain.block_number(), 0);
  (db, blockchain)
}

#[test]
fn block_addition() {
  let genesis = new_genesis();
  let validators = Arc::new(Validators::new(genesis, vec![]).unwrap());
  let (db, mut blockchain) = new_blockchain::<SignedTransaction>(genesis, &[]);
  let block = blockchain.build_block::<N>(validators.clone());

  assert_eq!(block.header.parent, genesis);
  assert_eq!(block.header.transactions, [0; 32]);
  blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
  assert!(blockchain.add_block::<N>(&block, vec![], validators).is_ok());
  assert_eq!(blockchain.tip(), block.hash());
  assert_eq!(blockchain.block_number(), 1);
  assert_eq!(
    Blockchain::<MemDb, SignedTransaction>::block_after(&db, genesis, &block.parent()).unwrap(),
    block.hash()
  );
}

#[test]
fn invalid_block() {
  let genesis = new_genesis();
  let validators = Arc::new(Validators::new(genesis, vec![]).unwrap());
  let (_, mut blockchain) = new_blockchain::<SignedTransaction>(genesis, &[]);

  let block = blockchain.build_block::<N>(validators.clone());

  // Mutate parent
  {
    #[allow(clippy::redundant_clone)] // False positive
    let mut block = block.clone();
    block.header.parent = Blake2s256::digest(block.header.parent).into();
    assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());
  }

  // Mutate tranactions merkle
  {
    let mut block = block;
    block.header.transactions = Blake2s256::digest(block.header.transactions).into();
    assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());
  }

  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 0);

  // Not a participant
  {
    // Manually create the block to bypass build_block's checks
    let block = Block::new(blockchain.tip(), vec![], vec![Transaction::Application(tx.clone())]);
    assert_eq!(block.header.transactions, merkle(&[tx.hash()]));
    assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());
  }

  // Run the rest of the tests with them as a participant
  let (_, blockchain) = new_blockchain(genesis, &[tx.1.signer]);

  // Re-run the not a participant block to make sure it now works
  {
    let block = Block::new(blockchain.tip(), vec![], vec![Transaction::Application(tx.clone())]);
    assert_eq!(block.header.transactions, merkle(&[tx.hash()]));
    blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
  }

  {
    // Add a valid transaction
    let mut blockchain = blockchain.clone();
    assert!(blockchain.add_transaction::<N>(true, Transaction::Application(tx.clone()), validators.clone()));
    let mut block = blockchain.build_block::<N>(validators.clone());
    assert_eq!(block.header.transactions, merkle(&[tx.hash()]));
    blockchain.verify_block::<N>(&block, validators.clone()).unwrap();

    // And verify mutating the transactions merkle now causes a failure
    block.header.transactions = merkle(&[]);
    assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());
  }

  {
    // Invalid nonce
    let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 5);
    // Manually create the block to bypass build_block's checks
    let block = Block::new(blockchain.tip(), vec![], vec![Transaction::Application(tx)]);
    assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());
  }

  {
    // Invalid signature
    let mut blockchain = blockchain;
    assert!(blockchain.add_transaction::<N>(true, Transaction::Application(tx), validators.clone()));
    let mut block = blockchain.build_block::<N>(validators.clone());
    blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
    match &mut block.transactions[0] {
      Transaction::Application(tx) => {
        tx.1.signature.s += <Ristretto as Ciphersuite>::F::ONE;
      },
      _ => panic!("non-signed tx found")
    }
    assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());

    // Make sure this isn't because the merkle changed due to the transaction hash including the
    // signature (which it explicitly isn't allowed to anyways)
    assert_eq!(block.header.transactions, merkle(&[block.transactions[0].hash()]));
  }
}

#[test]
fn signed_transaction() {
  let genesis = new_genesis();
  let validators = Arc::new(Validators::new(genesis, vec![]).unwrap());
  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 0);
  let signer = tx.1.signer;

  let (_, mut blockchain) = new_blockchain::<SignedTransaction>(genesis, &[signer]);
  assert_eq!(blockchain.next_nonce(signer), Some(0));

  let test = |blockchain: &mut Blockchain<MemDb, SignedTransaction>,
              mempool: Vec<Transaction<SignedTransaction>>| {
    let tip = blockchain.tip();
    for tx in mempool.clone() {
      let Transaction::Application(tx) = tx else { panic!("tendermint tx found"); };
      let next_nonce = blockchain.next_nonce(signer).unwrap();
      assert!(blockchain.add_transaction::<N>(true, Transaction::Application(tx), validators.clone()));
      assert_eq!(next_nonce + 1, blockchain.next_nonce(signer).unwrap());
    }
    let block = blockchain.build_block::<N>(validators.clone());
    assert_eq!(block, Block::new(blockchain.tip(), vec![], mempool.clone()));
    assert_eq!(blockchain.tip(), tip);
    assert_eq!(block.header.parent, tip);

    // Make sure all transactions were included
    assert_eq!(block.transactions, mempool);
    // Make sure the merkle was correct
    assert_eq!(
      block.header.transactions,
      merkle(&mempool.iter().map(Transaction::hash).collect::<Vec<_>>())
    );

    // Verify and add the block
    blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
    assert!(blockchain.add_block::<N>(&block, vec![], validators.clone()).is_ok());
    assert_eq!(blockchain.tip(), block.hash());
  };

  // Test with a single nonce
  test(&mut blockchain, vec![Transaction::Application(tx)]);
  assert_eq!(blockchain.next_nonce(signer), Some(1));

  // Test with a flood of nonces
  let mut mempool = vec![];
  for nonce in 1 .. 64 {
    mempool.push(Transaction::Application(crate::tests::signed_transaction(&mut OsRng, genesis, &key, nonce)));
  }
  test(&mut blockchain, mempool);
  assert_eq!(blockchain.next_nonce(signer), Some(64));
}

#[test]
fn provided_transaction() {
  let genesis = new_genesis();
  let validators = Arc::new(Validators::new(genesis, vec![]).unwrap());
  let (_, mut blockchain) = new_blockchain::<ProvidedTransaction>(genesis, &[]);

  let tx = random_provided_transaction(&mut OsRng);

  // This should be provideable
  let mut db = MemDb::new();
  let mut txs = ProvidedTransactions::<_, ProvidedTransaction>::new(db.clone(), genesis);
  txs.provide(tx.clone()).unwrap();
  assert_eq!(txs.provide(tx.clone()), Err(ProvidedError::AlreadyProvided));
  assert_eq!(
    ProvidedTransactions::<_, ProvidedTransaction>::new(db.clone(), genesis).transactions,
    HashMap::from([("provided", VecDeque::from([tx.clone()]))]),
  );
  let mut txn = db.txn();
  txs.complete(&mut txn, "provided", tx.hash());
  txn.commit();
  assert!(ProvidedTransactions::<_, ProvidedTransaction>::new(db.clone(), genesis)
    .transactions
    .is_empty());

  // Non-provided transactions should fail verification
  let block = Block::new(blockchain.tip(), vec![tx.clone()], vec![]);
  assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());

  // Provided transactions should pass verification
  blockchain.provide_transaction(tx.clone()).unwrap();
  blockchain.verify_block::<N>(&block, validators.clone()).unwrap();

  // add_block should work for verified blocks
  assert!(blockchain.add_block::<N>(&block, vec![], validators.clone()).is_ok());

  let block = Block::new(blockchain.tip(), vec![tx], vec![]);
  // The provided transaction should no longer considered provided, causing this error
  assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());
  // add_block should fail for unverified provided transactions if told to add them
  assert!(blockchain.add_block::<N>(&block, vec![], validators.clone()).is_err());
}
