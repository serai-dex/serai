use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Ristretto};

use serai_db::{DbTxn, Db};
use tendermint::ext::Network;

use crate::{
  Transaction,
  ACCOUNT_MEMPOOL_LIMIT, tendermint::tx::verify_tendermint_tx,
  transaction::{Signed, TransactionKind, Transaction as TransactionTrait, verify_transaction},
};

use crate::ReadWrite;

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

  /// save given tx to the mempool db
  fn save_tx(&mut self, tx: Transaction<T>) {
    let tx_hash = tx.hash();
    let transaction_key = self.transaction_key(&tx_hash);
    let current_mempool_key = self.current_mempool_key();
    let mut current_mempool = self.db.get(&current_mempool_key).unwrap_or(vec![]);

    let mut txn = self.db.txn();
    txn.put(transaction_key, tx.serialize());
    current_mempool.extend(tx_hash);
    txn.put(current_mempool_key, current_mempool);
    txn.commit();

    self.txs.insert(tx_hash, tx);
  }

  fn unsigned_already_exist(&self, unsigned_included: &[[u8; 32]], hash: [u8; 32]) -> bool {
    // check we have the tx in the pool/chain
    let res = unsigned_included.iter().find(|&&tx_hash| {
      tx_hash == hash
    });
    if res.is_some() || self.txs.contains_key(&hash){
      return true;
    }

    false
  }

  pub(crate) fn new(db: D, genesis: [u8; 32]) -> Self {
    let mut res = Mempool { db, genesis, txs: HashMap::<[u8; 32], Transaction<T>>::new(), next_nonces: HashMap::new() };

    let current_mempool = res.db.get(res.current_mempool_key()).unwrap_or(vec![]);
    let mut hash = [0; 32];
    let mut i = 0;
    while i < current_mempool.len() {
      hash.copy_from_slice(&current_mempool[i .. (i + 32)]);
      let tx: Transaction<T> =
        Transaction::read::<&[u8]>(&mut res.db.get(res.transaction_key(&hash)).unwrap().as_ref()).unwrap();

      debug_assert_eq!(tx.hash(), hash);
      match tx {
        Transaction::Tendermint(tx) => {
          res.txs.insert(hash, Transaction::Tendermint(tx));
        },
        Transaction::Application(tx) => {
          match tx.kind() {
            TransactionKind::Signed(Signed { signer, nonce, .. }) => {
              if let Some(prev) = res.next_nonces.insert(*signer, nonce + 1) {
                // These mempool additions should've been ordered
                assert!(prev < *nonce);
              }
              res.txs.insert(hash, Transaction::Application(tx));
            }
            _ => panic!("mempool database had a non-signed application transaction"),
          }
        }
      }

      i += 32;
    }

    res
  }

  /// Returns true if this is a valid, new transaction.
  pub(crate) fn add<N: Network>(
    &mut self,
    blockchain_next_nonces: &HashMap<<Ristretto as Ciphersuite>::G, u32>,
    unsigned_included: &[[u8; 32]],
    internal: bool,
    tx: Transaction<T>,
    schema: N::SignatureScheme
  ) -> bool {
    match &tx {
      Transaction::Tendermint(tendermint_tx) => {
        assert_eq!(TransactionKind::Unsigned, tendermint_tx.kind());

        // check we have the tx in the pool/chain
        if self.unsigned_already_exist(unsigned_included, tx.hash()) {
          // TODO: should this return true? function comment says return false
          // if not a new tx.
          return false;
        }

        // verify the tx
        if verify_tendermint_tx::<N>(tendermint_tx, self.genesis, schema).is_err() {
          return false;
        }

        self.save_tx(tx);
        true
      },
      Transaction::Application(app_tx) => {
        match app_tx.kind() {
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

            if verify_transaction(app_tx, self.genesis, &mut self.next_nonces).is_err() {
              return false;
            }
            assert_eq!(self.next_nonces[signer], nonce + 1);

            // save tx to the pool
            self.save_tx(tx);

            true
          },
          _ => false,
        }
      }
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
  ) -> Vec<Transaction<T>> {
    let mut res = vec![];
    for hash in self.txs.keys().cloned().collect::<Vec<_>>() {
      let tx = &self.txs[&hash];

      // Verify this hasn't gone stale
      if let Transaction::Application(tx) =  tx {
        match tx.kind() {
          TransactionKind::Signed(Signed { signer, nonce, .. }) => {
            if blockchain_next_nonces[signer] > *nonce {
              self.remove(&hash);
              continue;
            }
          }
          _ => panic!("non-signed transaction entered mempool"),
        }
      }

      // Since this TX isn't stale, include it
      // TODO: This also includes non-signed Tendermint Evidence txs. should it?
      res.push(tx.clone());
    }

    // Sort res by nonce.
    let nonce = |tx: &Transaction<T>| {
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
    let transaction_key = self.transaction_key(tx);
    let current_mempool_key = self.current_mempool_key();
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
