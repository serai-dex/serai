use std::collections::{HashSet, HashMap};

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use blake2::{Digest, Blake2s256};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use crate::{
  merkle, Transaction, ProvidedTransactions, Block, Blockchain,
  tests::{ProvidedTransaction, SignedTransaction, random_provided_transaction},
};

fn new_blockchain<T: Transaction>() -> ([u8; 32], Blockchain<T>) {
  let mut genesis = [0; 32];
  OsRng.fill_bytes(&mut genesis);

  let blockchain = Blockchain::new(genesis);
  assert_eq!(blockchain.tip(), genesis);

  (genesis, blockchain)
}

#[test]
fn block_addition() {
  let (genesis, mut blockchain) = new_blockchain::<SignedTransaction>();
  let block = blockchain.build_block(HashMap::new());
  assert_eq!(block.header.parent, genesis);
  assert_eq!(block.header.transactions, [0; 32]);
  blockchain.verify_block(&block).unwrap();
  blockchain.add_block(&block);
  assert_eq!(blockchain.tip(), block.hash());
}

#[test]
fn invalid_block() {
  let (genesis, blockchain) = new_blockchain::<SignedTransaction>();

  let block = blockchain.build_block(HashMap::new());

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

  {
    // Add a valid transaction
    let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 0);
    let mut block = blockchain.build_block(HashMap::from([(tx.hash(), tx.clone())]));
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
    let block =
      Block::new(blockchain.tip(), &ProvidedTransactions::new(), HashMap::from([(tx.hash(), tx)]));
    assert!(blockchain.verify_block(&block).is_err());
  }

  {
    // Invalid signature
    let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 0);
    let mut block = blockchain.build_block(HashMap::from([(tx.hash(), tx)]));
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
  let (genesis, mut blockchain) = new_blockchain::<SignedTransaction>();
  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, 0);
  let signer = tx.1.signer;
  assert_eq!(blockchain.next_nonce(signer), 0);

  let test = |blockchain: &mut Blockchain<SignedTransaction>, mempool: HashMap<_, _>| {
    let mut hashes = mempool.keys().cloned().collect::<HashSet<_>>();

    let tip = blockchain.tip();
    let block = blockchain.build_block(mempool);
    assert_eq!(blockchain.tip(), tip);
    assert_eq!(block.header.parent, tip);

    // Make sure all transactions were included
    let mut ordered_hashes = vec![];
    assert_eq!(hashes.len(), block.transactions.len());
    for transaction in &block.transactions {
      let hash = transaction.hash();
      assert!(hashes.remove(&hash));
      ordered_hashes.push(hash);
    }
    // Make sure the merkle was correct
    assert_eq!(block.header.transactions, merkle(&ordered_hashes));

    // Verify and add the block
    blockchain.verify_block(&block).unwrap();
    blockchain.add_block(&block);
    assert_eq!(blockchain.tip(), block.hash());
  };

  // Test with a single nonce
  test(&mut blockchain, HashMap::from([(tx.hash(), tx)]));
  assert_eq!(blockchain.next_nonce(signer), 1);

  // Test with a flood of nonces
  let mut mempool = HashMap::new();
  let mut nonces = (1 .. 64).collect::<Vec<_>>();
  // Randomize insertion order into HashMap, even though it should already have unordered iteration
  while !nonces.is_empty() {
    let nonce = nonces.swap_remove(
      usize::try_from(OsRng.next_u64() % u64::try_from(nonces.len()).unwrap()).unwrap(),
    );
    let tx = crate::tests::signed_transaction(&mut OsRng, genesis, &key, nonce);
    mempool.insert(tx.hash(), tx);
  }
  test(&mut blockchain, mempool);
  assert_eq!(blockchain.next_nonce(signer), 64);
}

#[test]
fn provided_transaction() {
  let (_, mut blockchain) = new_blockchain::<ProvidedTransaction>();

  let tx = random_provided_transaction(&mut OsRng);
  let mut txs = ProvidedTransactions::new();
  txs.provide(tx.clone());
  // Non-provided transactions should fail verification
  let block = Block::new(blockchain.tip(), &txs, HashMap::new());
  assert!(blockchain.verify_block(&block).is_err());

  // Provided transactions should pass verification
  blockchain.provide_transaction(tx);
  blockchain.verify_block(&block).unwrap();

  // add_block should work for verified blocks
  blockchain.add_block(&block);

  let block = Block::new(blockchain.tip(), &txs, HashMap::new());
  // The provided transaction should no longer considered provided, causing this error
  assert!(blockchain.verify_block(&block).is_err());
  // add_block should also work for unverified provided transactions if told to add them
  blockchain.add_block(&block);
}
