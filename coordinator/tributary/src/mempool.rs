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

  last_nonce_in_mempool: HashMap<(<Ristretto as Ciphersuite>::G, Vec<u8>), u32>,
  txs: HashMap<[u8; 32], Transaction<T>>,
  txs_per_signer: HashMap<<Ristretto as Ciphersuite>::G, u32>,
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
    let mut res = Mempool {
      db,
      genesis,
      last_nonce_in_mempool: HashMap::new(),
      txs: HashMap::new(),
      txs_per_signer: HashMap::new(),
    };

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
        Transaction::Application(tx) => match tx.kind() {
          TransactionKind::Signed(order, Signed { signer, nonce, .. }) => {
            let amount = *res.txs_per_signer.get(signer).unwrap_or(&0) + 1;
            res.txs_per_signer.insert(*signer, amount);

            if let Some(prior_nonce) =
              res.last_nonce_in_mempool.insert((*signer, order.clone()), *nonce)
            {
              assert_eq!(prior_nonce, nonce - 1);
            }

            res.txs.insert(hash, Transaction::Application(tx));
          }
          TransactionKind::Unsigned => {
            res.txs.insert(hash, Transaction::Application(tx));
          }
          _ => panic!("mempool database had a provided transaction"),
        },
      }
    }

    res
  }

  // Returns Ok(true) if new, Ok(false) if an already present unsigned, or the error.
  pub(crate) fn add<
    N: Network,
    F: FnOnce(<Ristretto as Ciphersuite>::G, Vec<u8>) -> Option<u32>,
  >(
    &mut self,
    blockchain_next_nonce: F,
    internal: bool,
    tx: Transaction<T>,
    schema: &N::SignatureScheme,
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
          TransactionKind::Signed(order, Signed { signer, .. }) => {
            // Get the nonce from the blockchain
            let Some(blockchain_next_nonce) = blockchain_next_nonce(*signer, order.clone()) else {
              // Not a participant
              Err(TransactionError::InvalidSigner)?
            };
            let mut next_nonce = blockchain_next_nonce;

            if let Some(mempool_last_nonce) =
              self.last_nonce_in_mempool.get(&(*signer, order.clone()))
            {
              assert!(*mempool_last_nonce >= blockchain_next_nonce);
              next_nonce = *mempool_last_nonce + 1;
            }

            // If we have too many transactions from this sender, don't add this yet UNLESS we are
            // this sender
            let amount_in_pool = *self.txs_per_signer.get(signer).unwrap_or(&0) + 1;
            if !internal && (amount_in_pool > ACCOUNT_MEMPOOL_LIMIT) {
              Err(TransactionError::TooManyInMempool)?;
            }

            verify_transaction(app_tx, self.genesis, &mut |_, _| Some(next_nonce))?;
            self.last_nonce_in_mempool.insert((*signer, order.clone()), next_nonce);
            self.txs_per_signer.insert(*signer, amount_in_pool);
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
  pub(crate) fn next_nonce_in_mempool(
    &self,
    signer: &<Ristretto as Ciphersuite>::G,
    order: Vec<u8>,
  ) -> Option<u32> {
    self.last_nonce_in_mempool.get(&(*signer, order)).copied().map(|nonce| nonce + 1)
  }

  /// Get transactions to include in a block.
  pub(crate) fn block(&mut self) -> Vec<Transaction<T>> {
    let mut unsigned = vec![];
    let mut signed = vec![];
    for hash in self.txs.keys().copied().collect::<Vec<_>>() {
      let tx = &self.txs[&hash];

      match tx.kind() {
        TransactionKind::Signed(_, Signed { .. }) => {
          signed.push(tx.clone());
        }
        TransactionKind::Unsigned => {
          unsigned.push(tx.clone());
        }
        _ => panic!("provided transaction entered mempool"),
      }
    }

    // Sort signed by nonce
    let nonce = |tx: &Transaction<T>| {
      if let TransactionKind::Signed(_, Signed { nonce, .. }) = tx.kind() {
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

    if let Some(tx) = self.txs.remove(tx) {
      if let TransactionKind::Signed(order, Signed { signer, nonce, .. }) = tx.kind() {
        let amount = *self.txs_per_signer.get(signer).unwrap() - 1;
        self.txs_per_signer.insert(*signer, amount);

        if self.last_nonce_in_mempool.get(&(*signer, order.clone())) == Some(nonce) {
          self.last_nonce_in_mempool.remove(&(*signer, order));
        }
      }
    }
  }

  #[cfg(test)]
  pub(crate) fn txs(&self) -> &HashMap<[u8; 32], Transaction<T>> {
    &self.txs
  }
}
