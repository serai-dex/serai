use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Ristretto};

use crate::{
  Signed, TransactionKind, Transaction, verify_transaction, ProvidedTransactions, BlockError,
  Block, Mempool,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Blockchain<T: Transaction> {
  genesis: [u8; 32],
  // TODO: db
  block_number: u64,
  tip: [u8; 32],
  next_nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,

  provided: ProvidedTransactions<T>,
  mempool: Mempool<T>,
}

impl<T: Transaction> Blockchain<T> {
  pub(crate) fn new(genesis: [u8; 32], participants: &[<Ristretto as Ciphersuite>::G]) -> Self {
    // TODO: Reload block_number/tip/next_nonces/provided/mempool

    let mut next_nonces = HashMap::new();
    for participant in participants {
      next_nonces.insert(*participant, 0);
    }

    Self {
      genesis,

      block_number: 0,
      tip: genesis,
      next_nonces,

      provided: ProvidedTransactions::new(),
      mempool: Mempool::new(genesis),
    }
  }

  pub(crate) fn tip(&self) -> [u8; 32] {
    self.tip
  }

  pub(crate) fn block_number(&self) -> u64 {
    self.block_number
  }

  pub(crate) fn add_transaction(&mut self, internal: bool, tx: T) -> bool {
    self.mempool.add(&self.next_nonces, internal, tx)
  }

  pub(crate) fn provide_transaction(&mut self, tx: T) -> bool {
    // TODO: Should this check be internal to ProvidedTransactions?
    if verify_transaction(&tx, self.genesis, &mut HashMap::new()).is_err() {
      return false;
    }
    self.provided.provide(tx);
    true
  }

  /// Returns the next nonce for signing, or None if they aren't a participant.
  pub(crate) fn next_nonce(&self, key: <Ristretto as Ciphersuite>::G) -> Option<u32> {
    Some(self.next_nonces.get(&key).cloned()?.max(self.mempool.next_nonce(&key).unwrap_or(0)))
  }

  pub(crate) fn build_block(&mut self) -> Block<T> {
    let block = Block::new(
      self.tip,
      self.provided.transactions.iter().cloned().collect(),
      self.mempool.block(&self.next_nonces),
    );
    // build_block should not return invalid blocks
    self.verify_block(&block).unwrap();
    block
  }

  pub(crate) fn verify_block(&self, block: &Block<T>) -> Result<(), BlockError> {
    block.verify(
      self.genesis,
      self.tip,
      &self.provided.transactions.iter().map(Transaction::hash).collect::<Vec<_>>(),
      self.next_nonces.clone(),
    )
  }

  /// Add a block.
  pub(crate) fn add_block(&mut self, block: &Block<T>) -> Result<(), BlockError> {
    self.verify_block(block)?;

    // None of the following assertions should be reachable since we verified the block
    self.tip = block.hash();
    self.block_number += 1;
    for tx in &block.transactions {
      match tx.kind() {
        TransactionKind::Provided => {
          self.provided.complete(tx.hash());
        }
        TransactionKind::Unsigned => {}
        TransactionKind::Signed(Signed { signer, nonce, .. }) => {
          let prev = self
            .next_nonces
            .insert(*signer, nonce + 1)
            .expect("block had signed transaction from non-participant");
          if prev != *nonce {
            panic!("verified block had an invalid nonce");
          }

          self.mempool.remove(&tx.hash());
        }
      }
    }

    Ok(())
  }
}
