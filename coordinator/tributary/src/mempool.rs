use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Ristretto};

use crate::{ACCOUNT_MEMPOOL_LIMIT, Signed, TransactionKind, Transaction, verify_transaction};

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Mempool<T: Transaction> {
  genesis: [u8; 32],
  txs: HashMap<[u8; 32], T>,
  next_nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,
}

impl<T: Transaction> Mempool<T> {
  pub(crate) fn new(genesis: [u8; 32]) -> Self {
    Mempool { genesis, txs: HashMap::new(), next_nonces: HashMap::new() }
  }

  /// Returns true if this is a valid, new transaction.
  pub(crate) fn add(
    &mut self,
    blockchain_next_nonces: &HashMap<<Ristretto as Ciphersuite>::G, u32>,
    internal: bool,
    tx: T,
  ) -> bool {
    match tx.kind() {
      TransactionKind::Signed(Signed { signer, nonce, .. }) => {
        // Get the nonce from the blockchain
        let Some(blockchain_next_nonce) = blockchain_next_nonces.get(signer).cloned() else {
          // Not a participant
          return false;
        };

        // If the blockchain's nonce is greater than the mempool's, use it
        // Default to true so if the mempool hasn't tracked this nonce yet, it'll be inserted
        let mut blockchain_is_greater = true;
        if let Some(mempool_next_nonce) = self.next_nonces.get(signer) {
          blockchain_is_greater = blockchain_next_nonce > *mempool_next_nonce;
        }

        if blockchain_is_greater {
          self.next_nonces.insert(*signer, blockchain_next_nonce);
        }

        // If we have too many transactions from this sender, don't add this yet UNLESS we are
        // this sender
        if !internal && (nonce >= &(blockchain_next_nonce + ACCOUNT_MEMPOOL_LIMIT)) {
          return false;
        }

        if verify_transaction(&tx, self.genesis, &mut self.next_nonces).is_err() {
          return false;
        }
        assert_eq!(self.next_nonces[signer], nonce + 1);

        self.txs.insert(tx.hash(), tx);
        true
      }
      _ => false,
    }
  }

  // Returns None if the mempool doesn't have a nonce tracked.
  pub(crate) fn next_nonce(&self, signer: &<Ristretto as Ciphersuite>::G) -> Option<u32> {
    self.next_nonces.get(signer).cloned()
  }

  /// Get transactions to include in a block.
  pub(crate) fn block(
    &mut self,
    blockchain_next_nonces: &HashMap<<Ristretto as Ciphersuite>::G, u32>,
  ) -> Vec<T> {
    let mut res = vec![];
    for hash in self.txs.keys().cloned().collect::<Vec<_>>() {
      let tx = &self.txs[&hash];
      // Verify this hasn't gone stale
      match tx.kind() {
        TransactionKind::Signed(Signed { signer, nonce, .. }) => {
          if blockchain_next_nonces[signer] > *nonce {
            self.txs.remove(&hash);
            continue;
          }
        }
        _ => panic!("non-signed transaction entered mempool"),
      }

      // Since this TX isn't stale, include it
      res.push(tx.clone());
    }

    // Sort res by nonce.
    let nonce = |tx: &T| {
      if let TransactionKind::Signed(Signed { nonce, .. }) = tx.kind() {
        *nonce
      } else {
        0
      }
    };
    res.sort_by(|a, b| nonce(a).partial_cmp(&nonce(b)).unwrap());

    res
  }

  /// Remove a transaction from the mempool.
  pub(crate) fn remove(&mut self, tx: &[u8; 32]) {
    self.txs.remove(tx);
  }

  #[cfg(test)]
  pub(crate) fn txs(&self) -> &HashMap<[u8; 32], T> {
    &self.txs
  }
}
