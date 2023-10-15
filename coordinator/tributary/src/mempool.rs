use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Ristretto};

use serai_db::{DbTxn, Db};

use tendermint::ext::{Network, Commit};

use crate::{
  ACCOUNT_MEMPOOL_LIMIT, ReadWrite,
  transaction::{
    Signed, TransactionKind, TransactionError, Transaction as TransactionTrait, verify_transaction,
  },
  tendermint::tx::verify_tendermint_tx,
  Transaction,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Mempool<D: Db, T: TransactionTrait> {
  db: D,
  genesis: [u8; 32],

  txs: HashMap<[u8; 32], Transaction<T>>,
  next_nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,
}

impl<D: Db, T: TransactionTrait> Mempool<D, T> {
  fn transaction_key(&self, hash: &[u8]) -> Vec<u8> {
    D::key(b"tributary_mempool", b"transaction", [self.genesis.as_ref(), hash].concat())
  }
  fn current_mempool_key(&self) -> Vec<u8> {
    D::key(b"tributary_mempool", b"current", self.genesis)
  }

  // save given tx to the mempool db
  fn save_tx(&mut self, tx: Transaction<T>) {
    let tx_hash = tx.hash();
    let transaction_key = self.transaction_key(&tx_hash);
    let current_mempool_key = self.current_mempool_key();
    #[allow(clippy::unwrap_or_default)]
    let mut current_mempool = self.db.get(&current_mempool_key).unwrap_or(vec![]);

    let mut txn = self.db.txn();
    txn.put(transaction_key, tx.serialize());
    current_mempool.extend(tx_hash);
    txn.put(current_mempool_key, current_mempool);
    txn.commit();

    self.txs.insert(tx_hash, tx);
  }

  fn unsigned_already_exist(
    &self,
    hash: [u8; 32],
    unsigned_in_chain: impl Fn([u8; 32]) -> bool,
  ) -> bool {
    unsigned_in_chain(hash) || self.txs.contains_key(&hash)
  }

  pub(crate) fn new(db: D, genesis: [u8; 32]) -> Self {
    let mut res = Mempool { db, genesis, txs: HashMap::new(), next_nonces: HashMap::new() };

    let current_mempool = res.db.get(res.current_mempool_key()).unwrap_or(vec![]);

    for hash in current_mempool.chunks(32) {
      let hash: [u8; 32] = hash.try_into().unwrap();
      let tx: Transaction<T> =
        Transaction::read::<&[u8]>(&mut res.db.get(res.transaction_key(&hash)).unwrap().as_ref())
          .unwrap();
      debug_assert_eq!(tx.hash(), hash);

      match tx {
        Transaction::Tendermint(tx) => {
          res.txs.insert(hash, Transaction::Tendermint(tx));
        }
        Transaction::Application(tx) => {
          match tx.kind() {
            TransactionKind::Signed(Signed { signer, nonce, .. }) => {
              if let Some(prev) = res.next_nonces.insert(*signer, nonce + 1) {
                // These mempool additions should've been ordered
                debug_assert!(prev < *nonce);
              }
              res.txs.insert(hash, Transaction::Application(tx));
            }
            TransactionKind::Unsigned => {
              res.txs.insert(hash, Transaction::Application(tx));
            }
            _ => panic!("mempool database had a provided transaction"),
          }
        }
      }
    }

    res
  }

  // Returns Ok(true) if new, Ok(false) if an already present unsigned, or the error.
  pub(crate) fn add<N: Network>(
    &mut self,
    blockchain_next_nonces: &HashMap<<Ristretto as Ciphersuite>::G, u32>,
    internal: bool,
    tx: Transaction<T>,
    schema: N::SignatureScheme,
    unsigned_in_chain: impl Fn([u8; 32]) -> bool,
    commit: impl Fn(u32) -> Option<Commit<N::SignatureScheme>>,
  ) -> Result<bool, TransactionError> {
    match &tx {
      Transaction::Tendermint(tendermint_tx) => {
        // All Tendermint transactions should be unsigned
        assert_eq!(TransactionKind::Unsigned, tendermint_tx.kind());

        // check we have the tx in the pool/chain
        if self.unsigned_already_exist(tx.hash(), unsigned_in_chain) {
          return Ok(false);
        }

        // verify the tx
        verify_tendermint_tx::<N>(tendermint_tx, schema, commit)?;
      }
      Transaction::Application(app_tx) => {
        match app_tx.kind() {
          TransactionKind::Signed(Signed { signer, nonce, .. }) => {
            // Get the nonce from the blockchain
            let Some(blockchain_next_nonce) = blockchain_next_nonces.get(signer).cloned() else {
              // Not a participant
              Err(TransactionError::InvalidSigner)?
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
              Err(TransactionError::TooManyInMempool)?;
            }

            verify_transaction(app_tx, self.genesis, &mut self.next_nonces)?;
            debug_assert_eq!(self.next_nonces[signer], nonce + 1);
          }
          TransactionKind::Unsigned => {
            // check we have the tx in the pool/chain
            if self.unsigned_already_exist(tx.hash(), unsigned_in_chain) {
              return Ok(false);
            }

            app_tx.verify()?;
          }
          TransactionKind::Provided(_) => Err(TransactionError::ProvidedAddedToMempool)?,
        }
      }
    }

    // Save the TX to the pool
    self.save_tx(tx);
    Ok(true)
  }

  // Returns None if the mempool doesn't have a nonce tracked.
  pub(crate) fn next_nonce(&self, signer: &<Ristretto as Ciphersuite>::G) -> Option<u32> {
    self.next_nonces.get(signer).cloned()
  }

  /// Get transactions to include in a block.
  pub(crate) fn block(
    &mut self,
    blockchain_next_nonces: &HashMap<<Ristretto as Ciphersuite>::G, u32>,
    unsigned_in_chain: impl Fn([u8; 32]) -> bool,
  ) -> Vec<Transaction<T>> {
    let mut unsigned = vec![];
    let mut signed = vec![];
    for hash in self.txs.keys().cloned().collect::<Vec<_>>() {
      let tx = &self.txs[&hash];

      // Verify this hasn't gone stale
      match tx.kind() {
        TransactionKind::Signed(Signed { signer, nonce, .. }) => {
          if blockchain_next_nonces[signer] > *nonce {
            self.remove(&hash);
            continue;
          }

          // Since this TX isn't stale, include it
          signed.push(tx.clone());
        }
        TransactionKind::Unsigned => {
          if unsigned_in_chain(hash) {
            self.remove(&hash);
            continue;
          }

          unsigned.push(tx.clone());
        }
        _ => panic!("provided transaction entered mempool"),
      }
    }

    // Sort signed by nonce
    let nonce = |tx: &Transaction<T>| {
      if let TransactionKind::Signed(Signed { nonce, .. }) = tx.kind() {
        *nonce
      } else {
        unreachable!()
      }
    };
    signed.sort_by(|a, b| nonce(a).partial_cmp(&nonce(b)).unwrap());

    // unsigned first, then signed.
    unsigned.append(&mut signed);
    unsigned
  }

  /// Remove a transaction from the mempool.
  pub(crate) fn remove(&mut self, tx: &[u8; 32]) {
    let transaction_key = self.transaction_key(tx);
    let current_mempool_key = self.current_mempool_key();
    #[allow(clippy::unwrap_or_default)]
    let current_mempool = self.db.get(&current_mempool_key).unwrap_or(vec![]);

    let mut i = 0;
    while i < current_mempool.len() {
      if &current_mempool[i .. (i + 32)] == tx {
        break;
      }
      i += 32;
    }

    // This doesn't have to be atomic with any greater operation
    let mut txn = self.db.txn();
    txn.del(transaction_key);
    if i != current_mempool.len() {
      txn
        .put(current_mempool_key, [&current_mempool[.. i], &current_mempool[(i + 32) ..]].concat());
    }
    txn.commit();

    self.txs.remove(tx);
  }

  #[cfg(test)]
  pub(crate) fn txs(&self) -> &HashMap<[u8; 32], Transaction<T>> {
    &self.txs
  }
}
