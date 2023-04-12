use std::collections::{HashSet, HashMap};

use ciphersuite::{Ciphersuite, Ristretto};

use crate::{Signed, TransactionKind, Transaction, verify_transaction};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mempool<T: Transaction> {
  genesis: [u8; 32],
  txs: HashMap<[u8; 32], T>,
  next_nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,
}

impl<T: Transaction> Mempool<T> {
  pub fn new(genesis: [u8; 32]) -> Self {
    Mempool { genesis, txs: HashMap::new(), next_nonces: HashMap::new() }
  }

  /// Returns true if this is a valid, new transaction.
  pub fn add(
    &mut self,
    blockchain_nonces: &HashMap<<Ristretto as Ciphersuite>::G, u32>,
    tx: T,
  ) -> bool {
    match tx.kind() {
      TransactionKind::Signed(Signed { signer, nonce, .. }) => {
        // If the mempool doesn't have a nonce tracked, grab it from the blockchain
        if !self.next_nonces.contains_key(signer) {
          // TODO: Same commentary here as present in verify_transaction about a whitelist
          self.next_nonces.insert(*signer, blockchain_nonces.get(signer).cloned().unwrap_or(0));
        }

        if verify_transaction(&tx, self.genesis, &mut HashSet::new(), &mut self.next_nonces)
          .is_err()
        {
          return false;
        }
        assert_eq!(self.next_nonces[signer], nonce + 1);

        self.txs.insert(tx.hash(), tx);
        true
      }
      _ => false,
    }
  }

  pub fn next_nonce(&self, signer: &<Ristretto as Ciphersuite>::G) -> Option<u32> {
    self.next_nonces.get(signer).cloned()
  }

  /// Get transactions to include in a block.
  pub fn block(
    &mut self,
    blockchain_nonces: &HashMap<<Ristretto as Ciphersuite>::G, u32>,
  ) -> HashMap<[u8; 32], T> {
    let mut res = HashMap::new();
    for hash in self.txs.keys().cloned().collect::<Vec<_>>() {
      let tx = &self.txs[&hash];
      // Verify this hasn't gone stale
      match tx.kind() {
        TransactionKind::Signed(Signed { signer, nonce, .. }) => {
          if blockchain_nonces.get(signer).cloned().unwrap_or(0) > *nonce {
            self.txs.remove(&hash);
            continue;
          }
        }
        _ => panic!("non-signed transaction entered mempool"),
      }

      // Since this TX isn't stale, include it
      res.insert(hash, tx.clone());
    }
    res
  }

  /// Remove a transaction from the mempool.
  pub fn remove(&mut self, tx: &[u8; 32]) {
    self.txs.remove(tx);
  }

  #[cfg(test)]
  pub(crate) fn txs(&self) -> &HashMap<[u8; 32], T> {
    &self.txs
  }
}
