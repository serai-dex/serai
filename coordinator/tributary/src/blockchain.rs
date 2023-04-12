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
  next_nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,
}

impl<T: Transaction> Blockchain<T> {
  pub fn new(genesis: [u8; 32], participants: &[<Ristretto as Ciphersuite>::G]) -> Self {
    // TODO: Reload provided/nonces

    let mut next_nonces = HashMap::new();
    for participant in participants {
      next_nonces.insert(*participant, 0);
    }
    Self { genesis, tip: genesis, provided: ProvidedTransactions::new(), next_nonces }
  }

  pub fn tip(&self) -> [u8; 32] {
    self.tip
  }

  pub fn provide_transaction(&mut self, tx: T) {
    self.provided.provide(tx)
  }

  /// Returns the next nonce, or None if they aren't a participant.
  pub fn next_nonce(&self, key: <Ristretto as Ciphersuite>::G) -> Option<u32> {
    self.next_nonces.get(&key).cloned()
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
    block.verify(self.genesis, self.tip, locally_provided, self.next_nonces.clone())
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
          let prev = self
            .next_nonces
            .insert(*signer, nonce + 1)
            .expect("block had signed transaction from non-participant");
          if prev != *nonce {
            panic!("block had an invalid nonce");
          }
        }
      }
    }
  }
}
