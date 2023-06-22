use std::{collections::{VecDeque, HashMap}, sync::Arc, io};

use lazy_static::__Deref;
use zeroize::Zeroizing;
use rand::rngs::OsRng;

use blake2::{Digest, Blake2s256};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use serai_db::{DbTxn, Db, MemDb};

use crate::{
  transaction::Transaction as TransactionTrait,
  merkle, ProvidedError, ProvidedTransactions, Block, Blockchain, Transaction,
  tests::{
    ProvidedTransaction, SignedTransaction, random_provided_transaction, p2p::LocalP2p,
    new_genesis, random_vote_tx, random_evidence_tx
  },
  tendermint::{TendermintNetwork, Validators, tx::TendermintTx, Signer, TendermintBlock},
  async_sequential, ReadWrite, TransactionKind, TransactionError, BlockError,
};

type N = TendermintNetwork<MemDb, SignedTransaction, LocalP2p>;

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
    let mut blockchain = blockchain.clone();
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

  {
    // invalid vote tx
    let mut blockchain = blockchain.clone();
    let vote_tx = random_vote_tx(&mut OsRng, genesis);
    assert!(blockchain.add_transaction::<N>(true, Transaction::Tendermint(vote_tx), validators.clone()));
    let mut block = blockchain.build_block::<N>(validators.clone());
    blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
    match &mut block.transactions[0] {
      Transaction::Tendermint(tx) => {
        match tx {
          TendermintTx::SlashVote(vote) => {
            vote.sig.signature.s += <Ristretto as Ciphersuite>::F::ONE;
          },
          _ =>  panic!("non-vote tx found")
        }
      },
      _ => panic!("non-tendermint tx found")
    }

    assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());

    // Make sure this isn't because the merkle changed due to the transaction hash including the
    // signature (which it explicitly isn't allowed to anyways)
    assert_eq!(block.header.transactions, merkle(&[block.transactions[0].hash()]));
  }

  // TODO: this test doesn't seem to make sense for evidence txs.
  // since they don't have a signature we have to modify the content,
  // so when we change them to make it invalid, merkle changes too.
  // so verify_block does fail on the merkle.
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

#[test]
fn tendermint_vote_tx() {
  let genesis = new_genesis();
  let validators = Arc::new(Validators::new(genesis, vec![]).unwrap());

  let (_, mut blockchain) = new_blockchain::<SignedTransaction>(genesis, &[]);

  let test = |blockchain: &mut Blockchain<MemDb, SignedTransaction>,
      mempool: Vec<Transaction<SignedTransaction>>| {
    let tip = blockchain.tip();
    for tx in mempool.clone() {
      let Transaction::Tendermint(tx) = tx else { panic!("non-tendermint tx found"); };
      assert!(blockchain.add_transaction::<N>(true, Transaction::Tendermint(tx), validators.clone()));
    }
    let block = blockchain.build_block::<N>(validators.clone());

    // TODO: this test doesn't make sense for unsigned txs, since they
    // don't have a particular order among themselves in a block, hence
    // block merkle might be different.
    // assert_eq!(block, Block::new(blockchain.tip(), vec![], mempool.clone()));
    assert_eq!(blockchain.tip(), tip);
    assert_eq!(block.header.parent, tip);

    // Make sure all transactions were included
    for bt in &block.transactions {
      assert!(mempool.contains(bt))
    }

    // Make sure the merkle was correct
    // TODO: again, merkle changes since the order of
    // transactions changes.
    // assert_eq!(
    //   block.header.transactions,
    //   merkle(&mempool.iter().map(Transaction::hash).collect::<Vec<_>>())
    // );

    // Verify and add the block
    blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
    assert!(blockchain.add_block::<N>(&block, vec![], validators.clone()).is_ok());
    assert_eq!(blockchain.tip(), block.hash());
  };

  // test with single tx
  let tx = random_vote_tx(&mut OsRng, genesis);
  test(&mut blockchain, vec![Transaction::Tendermint(tx)]);

  // test with multiple txs
  let mut mempool: Vec<Transaction<SignedTransaction>> = vec![];
  for _ in 0..5 {
    mempool.push(Transaction::Tendermint(random_vote_tx(&mut OsRng, genesis)));
  }
  test(&mut blockchain, mempool);
}



async_sequential!(

  async fn tendermint_evidence_tx() {
    let genesis = new_genesis();
    let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
    let signer = Signer::new(genesis, key.clone());
    let signer_id = Ristretto::generator() * key.deref();
    let mut validators = Arc::new(Validators::new(genesis, vec![(signer_id, 1)]).unwrap());

    let (_, mut blockchain) = new_blockchain::<SignedTransaction>(genesis, &[]);

    let test = |blockchain: &mut Blockchain<MemDb, SignedTransaction>,
        mempool: Vec<Transaction<SignedTransaction>>, validators: Arc<Validators>| {
      let tip = blockchain.tip();
      for tx in mempool.clone() {
        let Transaction::Tendermint(tx) = tx else { panic!("non-tendermint tx found"); };
        assert!(blockchain.add_transaction::<N>(true, Transaction::Tendermint(tx), validators.clone()));
      }
      let block = blockchain.build_block::<N>(validators.clone());
      assert_eq!(blockchain.tip(), tip);
      assert_eq!(block.header.parent, tip);

      // Make sure all transactions were included
      for bt in &block.transactions {
        assert!(mempool.contains(bt))
      }

      // Verify and add the block
      blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
      assert!(blockchain.add_block::<N>(&block, vec![], validators.clone()).is_ok());
      assert_eq!(blockchain.tip(), block.hash());
    };

    // test with single tx
    let tx = random_evidence_tx::<N>(signer.into(), TendermintBlock(vec![0x12])).await;
    test(&mut blockchain, vec![Transaction::Tendermint(tx)], validators.clone());

    // test with multiple txs
    let mut mempool: Vec<Transaction<SignedTransaction>> = vec![];
    let mut signers = vec![];
    for _ in 0..5 {
      let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
      let signer = Signer::new(genesis, key.clone());
      let signer_id = Ristretto::generator() * key.deref();
      signers.push((signer_id, 1));
      mempool.push(Transaction::Tendermint(random_evidence_tx::<N>(signer.into(), TendermintBlock(vec![0x12])).await));
    }

    // update validators
    validators = Arc::new(Validators::new(genesis, signers).unwrap());
    test(&mut blockchain, mempool, validators.clone());
  }
);

#[test]
fn block_tx_ordering() {

  #[derive(Debug, PartialEq, Eq, Clone)]
  enum SignedTx {
    Signed(SignedTransaction),
    Provided(ProvidedTransaction)
  }
  impl ReadWrite for SignedTx {
    fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
      let mut kind = [0];
      reader.read_exact(&mut kind)?;
      match kind[0] {
        0 => {
          Ok(SignedTx::Signed(SignedTransaction::read(reader)?))
        },
        1 => {
          Ok(SignedTx::Provided(ProvidedTransaction::read(reader)?))
        },
        _ => Err(io::Error::new(io::ErrorKind::Other, "invalid transaction type"))
      }
    }

    fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
      match self {
        SignedTx::Signed(signed) => {
          writer.write_all(&[0])?;
          signed.write(writer)
        },
        SignedTx::Provided(pro) => {
          writer.write_all(&[1])?;
          pro.write(writer)
        }
      }
    }
  }

  impl TransactionTrait for SignedTx {
    fn kind(&self) -> TransactionKind<'_> {
      match self {
        SignedTx::Signed(signed) => signed.kind(),
        SignedTx::Provided(pro) => pro.kind()
      }
    }

    fn hash(&self) -> [u8; 32] {
      match self {
        SignedTx::Signed(signed) => signed.hash(),
        SignedTx::Provided(pro) => pro.hash()
      }
    }

    fn verify(&self) -> Result<(), TransactionError> {
      Ok(())
    }
  }

  let genesis = new_genesis();
  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let validators = Arc::new(Validators::new(genesis, vec![]).unwrap());

  // signer
  let signed_raw = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 0);
  let signer = signed_raw.1.signer;

  // txs
  let signed_tx = SignedTx::Signed(signed_raw);
  let provided_tx = SignedTx::Provided(random_provided_transaction(&mut OsRng));
  let unsigned_tx = random_vote_tx(&mut OsRng, genesis);

  let (_, mut blockchain) = new_blockchain::<SignedTx>(genesis, &[signer]);
  let mempool = vec![
    Transaction::Application(signed_tx.clone()),
    Transaction::Tendermint(unsigned_tx.clone())
  ];

  // add txs
  let tip = blockchain.tip();
  assert!(blockchain.add_transaction::<N>(true, Transaction::Application(signed_tx), validators.clone()));
  assert!(blockchain.add_transaction::<N>(true, Transaction::Tendermint(unsigned_tx), validators.clone()));

  blockchain.provide_transaction(provided_tx.clone()).unwrap();
  let mut block = blockchain.build_block::<N>(validators.clone());

  assert_eq!(block, Block::new(blockchain.tip(), vec![provided_tx.clone()], mempool.clone()));
  assert_eq!(blockchain.tip(), tip);
  assert_eq!(block.header.parent, tip);

  // Make sure all transactions were included
  assert_eq!(block.transactions.len(), 3);

  // check the tx order
  let txs = &block.transactions;
  assert!(matches!(txs[0].kind(), TransactionKind::Provided(..)));
  assert!(matches!(txs[1].kind(), TransactionKind::Unsigned));
  assert!(matches!(txs[2].kind(), TransactionKind::Signed(..)));

  // should be a valid block
  blockchain.verify_block::<N>(&block, validators.clone()).unwrap();

  let txs_orig = block.transactions.clone();

  // modify tx order
  block.transactions.swap(0, 1);

  // should fail
  assert_eq!(blockchain.verify_block::<N>(&block, validators.clone()).unwrap_err(), BlockError::WrongTxOrder);

  // reset
  block.transactions = txs_orig.clone();

  // modify tx order
  block.transactions.swap(0, 2);

  // should fail
  assert_eq!(blockchain.verify_block::<N>(&block, validators.clone()).unwrap_err(), BlockError::WrongTxOrder);

  // reset
  block.transactions = txs_orig.clone();

  // modify tx order
  block.transactions.swap(1, 2);

  // should fail
  assert_eq!(blockchain.verify_block::<N>(&block, validators.clone()).unwrap_err(), BlockError::WrongTxOrder);

  // reset
  block.transactions = txs_orig;

  // should be valid block again
  blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
}
