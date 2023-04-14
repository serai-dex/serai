use zeroize::Zeroizing;
use rand::{RngCore, rngs::OsRng};

use blake2::{Digest, Blake2s256};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use crate::{
  merkle, Transaction, ProvidedTransactions, Block, Blockchain,
  tests::{ProvidedTransaction, SignedTransaction, random_provided_transaction},
};

fn new_genesis() -> [u8; 32] {
  let mut genesis = [0; 32];
  OsRng.fill_bytes(&mut genesis);
  genesis
}

fn new_blockchain<T: Transaction>(
  genesis: [u8; 32],
  participants: &[<Ristretto as Ciphersuite>::G],
) -> Blockchain<T> {
  let blockchain = Blockchain::new(genesis, participants);
  assert_eq!(blockchain.tip(), genesis);
  assert_eq!(blockchain.block_number(), 0);
  blockchain
}

#[test]
fn block_addition() {
  let genesis = new_genesis();
  let mut blockchain = new_blockchain::<SignedTransaction>(genesis, &[]);
  let block = blockchain.build_block();
  assert_eq!(block.header.parent, genesis);
  assert_eq!(block.header.transactions, [0; 32]);
  blockchain.verify_block(&block).unwrap();
  assert!(blockchain.add_block(&block).is_ok());
  assert_eq!(blockchain.tip(), block.hash());
  assert_eq!(blockchain.block_number(), 1);
}

#[test]
fn invalid_block() {
  let genesis = new_genesis();
  let mut blockchain = new_blockchain::<SignedTransaction>(genesis, &[]);

  let block = blockchain.build_block();

  // Mutate parent
  {
    #[allow(clippy::redundant_clone)] // False positive
    let mut block = block.clone();
    block.header.parent = Blake2s256::digest(block.header.parent).into();
    assert!(blockchain.verify_block(&block).is_err());
  }

  // Mutate tranactions merkle
  {
    let mut block = block;
    block.header.transactions = Blake2s256::digest(block.header.transactions).into();
    assert!(blockchain.verify_block(&block).is_err());
  }

  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 0);

  // Not a participant
  {
    // Manually create the block to bypass build_block's checks
    let block = Block::new(blockchain.tip(), vec![], vec![tx.clone()]);
    assert_eq!(block.header.transactions, merkle(&[tx.hash()]));
    assert!(blockchain.verify_block(&block).is_err());
  }

  // Run the rest of the tests with them as a participant
  let blockchain = new_blockchain(genesis, &[tx.1.signer]);

  // Re-run the not a participant block to make sure it now works
  {
    let block = Block::new(blockchain.tip(), vec![], vec![tx.clone()]);
    assert_eq!(block.header.transactions, merkle(&[tx.hash()]));
    blockchain.verify_block(&block).unwrap();
  }

  {
    // Add a valid transaction
    let mut blockchain = blockchain.clone();
    assert!(blockchain.add_transaction(true, tx.clone()));
    let mut block = blockchain.build_block();
    assert_eq!(block.header.transactions, merkle(&[tx.hash()]));
    blockchain.verify_block(&block).unwrap();

    // And verify mutating the transactions merkle now causes a failure
    block.header.transactions = merkle(&[]);
    assert!(blockchain.verify_block(&block).is_err());
  }

  {
    // Invalid nonce
    let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 5);
    // Manually create the block to bypass build_block's checks
    let block = Block::new(blockchain.tip(), vec![], vec![tx]);
    assert!(blockchain.verify_block(&block).is_err());
  }

  {
    // Invalid signature
    let mut blockchain = blockchain;
    assert!(blockchain.add_transaction(true, tx));
    let mut block = blockchain.build_block();
    blockchain.verify_block(&block).unwrap();
    block.transactions[0].1.signature.s += <Ristretto as Ciphersuite>::F::ONE;
    assert!(blockchain.verify_block(&block).is_err());

    // Make sure this isn't because the merkle changed due to the transaction hash including the
    // signature (which it explicitly isn't allowed to anyways)
    assert_eq!(block.header.transactions, merkle(&[block.transactions[0].hash()]));
  }
}

#[test]
fn signed_transaction() {
  let genesis = new_genesis();

  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 0);
  let signer = tx.1.signer;

  let mut blockchain = new_blockchain::<SignedTransaction>(genesis, &[signer]);
  assert_eq!(blockchain.next_nonce(signer), Some(0));

  let test = |blockchain: &mut Blockchain<SignedTransaction>, mempool: Vec<SignedTransaction>| {
    let tip = blockchain.tip();
    for tx in mempool.clone() {
      let next_nonce = blockchain.next_nonce(signer).unwrap();
      assert!(blockchain.add_transaction(true, tx));
      assert_eq!(next_nonce + 1, blockchain.next_nonce(signer).unwrap());
    }
    let block = blockchain.build_block();
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
    blockchain.verify_block(&block).unwrap();
    assert!(blockchain.add_block(&block).is_ok());
    assert_eq!(blockchain.tip(), block.hash());
  };

  // Test with a single nonce
  test(&mut blockchain, vec![tx]);
  assert_eq!(blockchain.next_nonce(signer), Some(1));

  // Test with a flood of nonces
  let mut mempool = vec![];
  for nonce in 1 .. 64 {
    mempool.push(crate::tests::signed_transaction(&mut OsRng, genesis, &key, nonce));
  }
  test(&mut blockchain, mempool);
  assert_eq!(blockchain.next_nonce(signer), Some(64));
}

#[test]
fn provided_transaction() {
  let mut blockchain = new_blockchain::<ProvidedTransaction>(new_genesis(), &[]);

  let tx = random_provided_transaction(&mut OsRng);

  // This should be provideable
  let mut txs = ProvidedTransactions::new();
  txs.provide(tx.clone());
  txs.complete(tx.hash());

  // Non-provided transactions should fail verification
  let block = Block::new(blockchain.tip(), vec![tx.clone()], vec![]);
  assert!(blockchain.verify_block(&block).is_err());

  // Provided transactions should pass verification
  blockchain.provide_transaction(tx.clone());
  blockchain.verify_block(&block).unwrap();

  // add_block should work for verified blocks
  assert!(blockchain.add_block(&block).is_ok());

  let block = Block::new(blockchain.tip(), vec![tx], vec![]);
  // The provided transaction should no longer considered provided, causing this error
  assert!(blockchain.verify_block(&block).is_err());
  // add_block should fail for unverified provided transactions if told to add them
  assert!(blockchain.add_block(&block).is_err());
}
