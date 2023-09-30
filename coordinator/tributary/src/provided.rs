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
  pub(crate) fn local_transaction_no_key(genesis: &[u8; 32], order: &str) -> Vec<u8> {
    D::key(b"tributary_provided", b"local", [genesis, order.as_bytes()].concat())
  }
  pub(crate) fn on_chain_transaction_no_key(genesis: &[u8; 32], order: &str) -> Vec<u8> {
    D::key(b"tributary_provided", b"on_chain", [genesis, order.as_bytes()].concat())
  }
  pub(crate) fn last_tx_block_order_key(
    genesis: &[u8; 32],
    hash: &[u8; 32],
    order: &str,
  ) -> Vec<u8> {
    D::key(b"tributary_provided", b"on_chain", [genesis, hash, order.as_bytes()].concat())
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

    // get local and on-chain tx numbers
    let local_key = Self::local_transaction_no_key(&self.genesis, order);
    let on_chain_key = Self::on_chain_transaction_no_key(&self.genesis, order);
    #[allow(clippy::unwrap_or_default)]
    let on_chain_tx_no = u32::from_le_bytes(
      self
        .db
        .get(on_chain_key)
        .unwrap_or(u32::try_from(0).unwrap().to_le_bytes().to_vec())
        .try_into()
        .unwrap(),
    );
    let mut local_tx_no = u32::from_le_bytes(
      self
        .db
        .get(&local_key)
        .unwrap_or(u32::try_from(0).unwrap().to_le_bytes().to_vec())
        .try_into()
        .unwrap(),
    );

    // try add to mempool if this is a new provided(we haven't seen it on-chain before).
    if local_tx_no >= on_chain_tx_no {
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

    // bump the tx number for the local order
    local_tx_no += 1;
    let mut txn = self.db.txn();
    txn.put(local_key, local_tx_no.to_le_bytes());
    txn.commit();

    Ok(())
  }

  /// Complete a provided transaction, no longer proposing it nor voting for its validity.
  pub(crate) fn complete(
    &mut self,
    txn: &mut D::Transaction<'_>,
    order: &'static str,
    block: [u8; 32],
    tx: [u8; 32],
  ) {
    let txs = self.transactions.get_mut(order);
    if txs.is_some() && txs.as_ref().unwrap().iter().any(|t| t.hash() == tx) {
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

    // bump the on-chain tx number.
    let on_chain_key = Self::on_chain_transaction_no_key(&self.genesis, order);
    let block_order_key = Self::last_tx_block_order_key(&self.genesis, &block, order);
    let mut on_chain_tx_no = u32::from_le_bytes(
      self
        .db
        .get(&on_chain_key)
        .unwrap_or(u32::try_from(0).unwrap().to_le_bytes().to_vec())
        .try_into()
        .unwrap(),
    );

    // TODO: use block hash or block number block-order key?
    // - Block hash is easy to use for keys and doesn't require additional api
    // but it takes up too much space.
    // - Block numbers are not that suitable as keys and requires additional tributary scanner
    // api(block_hash -> block_no) but doesn't take much space.

    // TODO: do we need both a global save and block-order save?
    // Technically it should be enough to save the tx for block-order only, but that requires
    // api change in `provide` function to take block hash as well(last block of the chain),
    // we should be able pass the last block from where we call it, but we do we want that?

    // save it
    on_chain_tx_no += 1;
    txn.put(on_chain_key, on_chain_tx_no.to_le_bytes());
    txn.put(block_order_key, on_chain_tx_no.to_le_bytes());
  }
}
