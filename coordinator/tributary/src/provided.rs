use std::collections::{VecDeque, HashMap};

use thiserror::Error;

use serai_db::{Get, DbTxn, Db};

use crate::transaction::{TransactionKind, TransactionError, Transaction, verify_transaction};

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum ProvidedError {
  /// The provided transaction's kind wasn't Provided
  #[error("transaction wasn't a provided transaction")]
  NotProvided,
  /// The provided transaction was invalid.
  #[error("provided transaction was invalid")]
  InvalidProvided(TransactionError),
  /// Transaction was already provided
  #[error("transaction was already provided")]
  AlreadyProvided,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProvidedTransactions<D: Db, T: Transaction> {
  db: D,
  genesis: [u8; 32],

  pub(crate) transactions: HashMap<&'static str, VecDeque<T>>,
}

impl<D: Db, T: Transaction> ProvidedTransactions<D, T> {
  fn transaction_key(&self, hash: &[u8]) -> Vec<u8> {
    D::key(b"tributary_provided", b"transaction", [self.genesis.as_ref(), hash].concat())
  }
  fn current_provided_key(&self) -> Vec<u8> {
    D::key(b"tributary_provided", b"current", self.genesis)
  }

  pub(crate) fn waiting_list_key(genesis: [u8; 32]) -> Vec<u8> {
    D::key(b"tributary_provided", b"waiting_list", genesis)
  }

  pub(crate) fn new(db: D, genesis: [u8; 32]) -> Self {
    let mut res = ProvidedTransactions { db, genesis, transactions: HashMap::new() };

    let currently_provided = res.db.get(res.current_provided_key()).unwrap_or(vec![]);
    let mut i = 0;
    while i < currently_provided.len() {
      let tx = T::read::<&[u8]>(
        &mut res.db.get(res.transaction_key(&currently_provided[i .. (i + 32)])).unwrap().as_ref(),
      )
      .unwrap();

      let TransactionKind::Provided(order) = tx.kind() else {
        panic!("provided transaction saved to disk wasn't provided");
      };

      if res.transactions.get(order).is_none() {
        res.transactions.insert(order, VecDeque::new());
      }
      res.transactions.get_mut(order).unwrap().push_back(tx);

      i += 32;
    }

    res
  }

  /// Provide a transaction for inclusion in a block.
  pub(crate) fn provide(&mut self, tx: T) -> Result<(), ProvidedError> {
    let TransactionKind::Provided(order) = tx.kind() else { Err(ProvidedError::NotProvided)? };

    match verify_transaction(&tx, self.genesis, &mut HashMap::new()) {
      Ok(()) => {}
      Err(e) => Err(ProvidedError::InvalidProvided(e))?,
    }

    let tx_hash = tx.hash();

    // get waiting list
    let waiting_list_key = Self::waiting_list_key(self.genesis);
    #[allow(clippy::unwrap_or_default)]
    let mut waiting_list = self.db.get(&waiting_list_key).unwrap_or(vec![]);

    // check whether this tx is a late provide
    let exist = waiting_list.chunks_exact(32).position(|h| {
      let hash: [u8; 32] = h.try_into().unwrap();
      hash == tx_hash
    });
    if let Some(i) = exist {
      // remove from the list since it is now arrived.
      let i = i * 32;
      assert_eq!(&waiting_list.drain(i .. (i + 32)).collect::<Vec<_>>(), &tx_hash);

      let mut txn = self.db.txn();
      txn.put(waiting_list_key, waiting_list);
      txn.commit();
    } else {
      // add to mempool if not

      // check whether we already have the tx in pool
      let provided_key = self.transaction_key(&tx_hash);
      if self.db.get(&provided_key).is_some() {
        Err(ProvidedError::AlreadyProvided)?;
      }

      let current_provided_key = self.current_provided_key();
      #[allow(clippy::unwrap_or_default)]
      let mut currently_provided = self.db.get(&current_provided_key).unwrap_or(vec![]);

      let mut txn = self.db.txn();
      txn.put(provided_key, tx.serialize());
      currently_provided.extend(tx_hash);
      txn.put(current_provided_key, currently_provided);
      txn.commit();

      if self.transactions.get(order).is_none() {
        self.transactions.insert(order, VecDeque::new());
      }
      self.transactions.get_mut(order).unwrap().push_back(tx);
    }

    Ok(())
  }

  /// Complete a provided transaction, no longer proposing it nor voting for its validity.
  pub(crate) fn complete(
    &mut self,
    txn: &mut D::Transaction<'_>,
    order: &'static str,
    tx: [u8; 32],
  ) {
    let txs = self.transactions.get_mut(order);
    if txs.as_ref().is_none() ||
      (txs.as_ref().is_some() && !txs.as_ref().unwrap().iter().any(|t| t.hash() == tx))
    {
      // we don't have this tx in our mempool, add it to waiting list.
      let waiting_list_key = Self::waiting_list_key(self.genesis);
      #[allow(clippy::unwrap_or_default)]
      let mut waiting_list = self.db.get(&waiting_list_key).unwrap_or(vec![]);

      waiting_list.extend(tx);
      txn.put(waiting_list_key, waiting_list);
    } else {
      assert_eq!(txs.unwrap().pop_front().unwrap().hash(), tx);

      let current_provided_key = self.current_provided_key();
      let mut currently_provided = txn.get(&current_provided_key).unwrap();

      // Find this TX's hash
      let mut i = 0;
      loop {
        if currently_provided[i .. (i + 32)] == tx {
          assert_eq!(&currently_provided.drain(i .. (i + 32)).collect::<Vec<_>>(), &tx);
          break;
        }

        i += 32;
        if i >= currently_provided.len() {
          panic!("couldn't find completed TX in currently provided");
        }
      }

      txn.put(current_provided_key, currently_provided);
    }
  }
}
