use core::ops::Deref;
use std::{
  collections::{VecDeque, HashMap},
  sync::Arc,
  io,
};

use zeroize::Zeroizing;
use rand::rngs::OsRng;

use blake2::{Digest, Blake2s256};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use serai_db::{DbTxn, Db, MemDb};

use crate::{
  ReadWrite, TransactionKind,
  transaction::Transaction as TransactionTrait,
  TransactionError, Transaction, ProvidedError, ProvidedTransactions, merkle, BlockError, Block,
  Blockchain,
  tendermint::{TendermintNetwork, Validators, tx::TendermintTx, Signer, TendermintBlock},
  tests::{
    ProvidedTransaction, SignedTransaction, random_provided_transaction, p2p::DummyP2p,
    new_genesis, random_vote_tx, random_evidence_tx,
  },
};

type N = TendermintNetwork<MemDb, SignedTransaction, DummyP2p>;

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
    assert!(blockchain.add_transaction::<N>(
      true,
      Transaction::Application(tx.clone()),
      validators.clone()
    ));
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
    assert!(blockchain.add_transaction::<N>(
      true,
      Transaction::Application(tx),
      validators.clone()
    ));
    let mut block = blockchain.build_block::<N>(validators.clone());
    blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
    match &mut block.transactions[0] {
      Transaction::Application(tx) => {
        tx.1.signature.s += <Ristretto as Ciphersuite>::F::ONE;
      }
      _ => panic!("non-signed tx found"),
    }
    assert!(blockchain.verify_block::<N>(&block, validators.clone()).is_err());

    // Make sure this isn't because the merkle changed due to the transaction hash including the
    // signature (which it explicitly isn't allowed to anyways)
    assert_eq!(block.header.transactions, merkle(&[block.transactions[0].hash()]));
  }

  {
    // Invalid vote signature
    let mut blockchain = blockchain.clone();
    let vote_tx = random_vote_tx(&mut OsRng, genesis);
    assert!(blockchain.add_transaction::<N>(
      true,
      Transaction::Tendermint(vote_tx),
      validators.clone()
    ));
    let mut block = blockchain.build_block::<N>(validators.clone());
    blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
    match &mut block.transactions[0] {
      Transaction::Tendermint(tx) => match tx {
        TendermintTx::SlashVote(vote) => {
          vote.sig.signature.s += <Ristretto as Ciphersuite>::F::ONE;
        }
        _ => panic!("non-vote tx found"),
      },
      _ => panic!("non-tendermint tx found"),
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
      let Transaction::Application(tx) = tx else {
        panic!("tendermint tx found");
      };
      let next_nonce = blockchain.next_nonce(signer).unwrap();
      assert!(blockchain.add_transaction::<N>(
        true,
        Transaction::Application(tx),
        validators.clone()
      ));
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
    mempool.push(Transaction::Application(crate::tests::signed_transaction(
      &mut OsRng, genesis, &key, nonce,
    )));
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
      let Transaction::Tendermint(tx) = tx else {
        panic!("non-tendermint tx found");
      };
      assert!(blockchain.add_transaction::<N>(
        true,
        Transaction::Tendermint(tx),
        validators.clone()
      ));
    }
    let block = blockchain.build_block::<N>(validators.clone());

    assert_eq!(blockchain.tip(), tip);
    assert_eq!(block.header.parent, tip);

    // Make sure all transactions were included
    for bt in &block.transactions {
      assert!(mempool.contains(bt));
    }

    // Make sure the merkle was correct
    // Uses block.transactions instead of mempool as order may differ between the two
    assert_eq!(
      block.header.transactions,
      merkle(&block.transactions.iter().map(Transaction::hash).collect::<Vec<_>>()),
    );

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
  for _ in 0 .. 5 {
    mempool.push(Transaction::Tendermint(random_vote_tx(&mut OsRng, genesis)));
  }
  test(&mut blockchain, mempool);
}

#[tokio::test]
async fn tendermint_evidence_tx() {
  let genesis = new_genesis();
  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let signer = Signer::new(genesis, key.clone());
  let signer_id = Ristretto::generator() * key.deref();
  let validators = Arc::new(Validators::new(genesis, vec![(signer_id, 1)]).unwrap());

  let (_, mut blockchain) = new_blockchain::<SignedTransaction>(genesis, &[]);

  let test = |blockchain: &mut Blockchain<MemDb, SignedTransaction>,
              mempool: Vec<Transaction<SignedTransaction>>,
              validators: Arc<Validators>| {
    let tip = blockchain.tip();
    for tx in mempool.clone() {
      let Transaction::Tendermint(tx) = tx else {
        panic!("non-tendermint tx found");
      };
      assert!(blockchain.add_transaction::<N>(
        true,
        Transaction::Tendermint(tx),
        validators.clone()
      ));
    }
    let block = blockchain.build_block::<N>(validators.clone());
    assert_eq!(blockchain.tip(), tip);
    assert_eq!(block.header.parent, tip);

    // Make sure all transactions were included
    for bt in &block.transactions {
      assert!(mempool.contains(bt));
    }

    // Verify and add the block
    blockchain.verify_block::<N>(&block, validators.clone()).unwrap();
    assert!(blockchain.add_block::<N>(&block, vec![], validators.clone()).is_ok());
    assert_eq!(blockchain.tip(), block.hash());
  };

  // test with single tx
  let tx = random_evidence_tx::<N>(signer.into(), TendermintBlock(vec![0x12])).await;
  test(&mut blockchain, vec![Transaction::Tendermint(tx)], validators);

  // test with multiple txs
  let mut mempool: Vec<Transaction<SignedTransaction>> = vec![];
  let mut signers = vec![];
  for _ in 0 .. 5 {
    let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
    let signer = Signer::new(genesis, key.clone());
    let signer_id = Ristretto::generator() * key.deref();
    signers.push((signer_id, 1));
    mempool.push(Transaction::Tendermint(
      random_evidence_tx::<N>(signer.into(), TendermintBlock(vec![0x12])).await,
    ));
  }

  // update validators
  let validators = Arc::new(Validators::new(genesis, signers).unwrap());
  test(&mut blockchain, mempool, validators);
}

#[test]
fn block_tx_ordering() {
  #[derive(Debug, PartialEq, Eq, Clone)]
  enum SignedTx {
    Signed(Box<SignedTransaction>),
    Provided(Box<ProvidedTransaction>),
  }
  impl ReadWrite for SignedTx {
    fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
      let mut kind = [0];
      reader.read_exact(&mut kind)?;
      match kind[0] {
        0 => Ok(SignedTx::Signed(Box::new(SignedTransaction::read(reader)?))),
        1 => Ok(SignedTx::Provided(Box::new(ProvidedTransaction::read(reader)?))),
        _ => Err(io::Error::new(io::ErrorKind::Other, "invalid transaction type")),
      }
    }

    fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
      match self {
        SignedTx::Signed(signed) => {
          writer.write_all(&[0])?;
          signed.write(writer)
        }
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
        SignedTx::Provided(pro) => pro.kind(),
      }
    }

    fn hash(&self) -> [u8; 32] {
      match self {
        SignedTx::Signed(signed) => signed.hash(),
        SignedTx::Provided(pro) => pro.hash(),
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
  let signer = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 0).1.signer;

  let (_, mut blockchain) = new_blockchain::<SignedTx>(genesis, &[signer]);
  let tip = blockchain.tip();

  // add txs
  let mut mempool = vec![];
  let mut provided_txs = vec![];
  for i in 0 .. 128 {
    let signed_tx = Transaction::Application(SignedTx::Signed(Box::new(
      crate::tests::signed_transaction(&mut OsRng, genesis, &key, i),
    )));
    assert!(blockchain.add_transaction::<N>(true, signed_tx.clone(), validators.clone()));
    mempool.push(signed_tx);

    let unsigned_tx = Transaction::Tendermint(random_vote_tx(&mut OsRng, genesis));
    assert!(blockchain.add_transaction::<N>(true, unsigned_tx.clone(), validators.clone()));
    mempool.push(unsigned_tx);

    let provided_tx = SignedTx::Provided(Box::new(random_provided_transaction(&mut OsRng)));
    blockchain.provide_transaction(provided_tx.clone()).unwrap();
    provided_txs.push(provided_tx);
  }
  let block = blockchain.build_block::<N>(validators.clone());

  assert_eq!(blockchain.tip(), tip);
  assert_eq!(block.header.parent, tip);

  // Make sure all transactions were included
  assert_eq!(block.transactions.len(), 3 * 128);
  for bt in &block.transactions[128 ..] {
    assert!(mempool.contains(bt));
  }

  // check the tx order
  let txs = &block.transactions;
  for tx in txs.iter().take(128) {
    assert!(matches!(tx.kind(), TransactionKind::Provided(..)));
  }
  for tx in txs.iter().take(128).skip(128) {
    assert!(matches!(tx.kind(), TransactionKind::Unsigned));
  }
  for tx in txs.iter().take(128).skip(256) {
    assert!(matches!(tx.kind(), TransactionKind::Signed(..)));
  }

  // should be a valid block
  blockchain.verify_block::<N>(&block, validators.clone()).unwrap();

  // Unsigned before Provided
  {
    let mut block = block.clone();
    // Doesn't use swap to preserve the order of Provided, as that's checked before kind ordering
    let unsigned = block.transactions.remove(128);
    block.transactions.insert(0, unsigned);
    assert_eq!(
      blockchain.verify_block::<N>(&block, validators.clone()).unwrap_err(),
      BlockError::WrongTransactionOrder
    );
  }

  // Signed before Provided
  {
    let mut block = block.clone();
    let signed = block.transactions.remove(256);
    block.transactions.insert(0, signed);
    assert_eq!(
      blockchain.verify_block::<N>(&block, validators.clone()).unwrap_err(),
      BlockError::WrongTransactionOrder
    );
  }

  // Signed before Unsigned
  {
    let mut block = block;
    block.transactions.swap(128, 256);
    assert_eq!(
      blockchain.verify_block::<N>(&block, validators.clone()).unwrap_err(),
      BlockError::WrongTransactionOrder
    );
  }
}
