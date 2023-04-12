use std::collections::{HashSet, HashMap};

use ciphersuite::{Ciphersuite, Ristretto};

use crate::{Signed, TransactionKind, Transaction, ProvidedTransactions, BlockError, Block};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Blockchain<T: Transaction> {
  genesis: [u8; 32],
  // TODO: db
  tip: [u8; 32],
  provided: ProvidedTransactions<T>,
  // TODO: Mempool
  nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,
}

impl<T: Transaction> Blockchain<T> {
  pub fn new(genesis: [u8; 32]) -> Self {
    // TODO: Reload provided/nonces
    Self { genesis, tip: genesis, provided: ProvidedTransactions::new(), nonces: HashMap::new() }
  }

  pub fn tip(&self) -> [u8; 32] {
    self.tip
  }

  pub fn provide_transaction(&mut self, tx: T) {
    self.provided.provide(tx)
  }

  pub fn next_nonce(&self, key: <Ristretto as Ciphersuite>::G) -> u32 {
    self.nonces.get(&key).cloned().unwrap_or(0)
  }

  // TODO: Embed mempool
  pub fn build_block(&self, txs: HashMap<[u8; 32], T>) -> Block<T> {
    let block = Block::new(self.tip, &self.provided, txs);
    // build_block should not return invalid blocks
    self.verify_block(&block).unwrap();
    block
  }

  pub fn verify_block(&self, block: &Block<T>) -> Result<(), BlockError> {
    let mut locally_provided = HashSet::new();
    for provided in self.provided.transactions.keys() {
      locally_provided.insert(*provided);
    }
    block.verify(self.genesis, self.tip, locally_provided, self.nonces.clone())
  }

  /// Add a block, assuming it's valid.
  ///
  /// Do not call this without either verifying the block or having it confirmed under consensus.
  /// Doing so will cause a panic or action an invalid transaction.
  pub fn add_block(&mut self, block: &Block<T>) {
    self.tip = block.hash();
    for tx in &block.transactions {
      match tx.kind() {
        TransactionKind::Provided => {
          self.provided.withdraw(tx.hash());
        }
        TransactionKind::Unsigned => {}
        TransactionKind::Signed(Signed { signer, nonce, .. }) => {
          if let Some(prev) = self.nonces.insert(*signer, nonce + 1) {
            if prev != *nonce {
              panic!("block had an invalid nonce");
            }
          }
        }
      }
    }
  }
}
