use std::collections::{VecDeque, HashMap};

use thiserror::Error;

use serai_db::{Get, DbTxn, Db};

use crate::transaction::{TransactionKind, TransactionError, Transaction, verify_transaction};

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum ProvidedError {
  /// The provided transaction's kind wasn't Provided
  #[error("transaction wasn't a provided transaction")]
  NotProvided,
  /// The provided transaction was invalid
  #[error("provided transaction was invalid")]
  InvalidProvided(TransactionError),
  /// Transaction was already provided
  #[error("transaction was already provided")]
  AlreadyProvided,
  /// Local transaction mismatches the on-chain provided
  #[error("local provides mismatches on-chain provided")]
  LocalMismatchesOnChain,
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
  pub(crate) fn locally_provided_quantity_key(genesis: &[u8; 32], order: &str) -> Vec<u8> {
    D::key(b"tributary_provided", b"local_quantity", [genesis, order.as_bytes()].concat())
  }
  pub(crate) fn on_chain_provided_quantity_key(genesis: &[u8; 32], order: &str) -> Vec<u8> {
    D::key(b"tributary_provided", b"on_chain_quantity", [genesis, order.as_bytes()].concat())
  }
  pub(crate) fn block_provided_quantity_key(
    genesis: &[u8; 32],
    block: &[u8; 32],
    order: &str,
  ) -> Vec<u8> {
    D::key(b"tributary_provided", b"block_quantity", [genesis, block, order.as_bytes()].concat())
  }

  pub(crate) fn on_chain_provided_key(genesis: &[u8; 32], order: &str, id: u32) -> Vec<u8> {
    D::key(
      b"tributary_provided",
      b"on_chain_tx",
      [genesis, order.as_bytes(), &id.to_le_bytes()].concat(),
    )
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

      if !res.transactions.contains_key(order) {
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

    match verify_transaction(&tx, self.genesis, &mut |_, _| None) {
      Ok(()) => {}
      Err(e) => Err(ProvidedError::InvalidProvided(e))?,
    }
    let tx_hash = tx.hash();

    // Check it wasn't already provided
    let provided_key = self.transaction_key(&tx_hash);
    if self.db.get(&provided_key).is_some() {
      Err(ProvidedError::AlreadyProvided)?;
    }

    // get local and on-chain tx numbers
    let local_key = Self::locally_provided_quantity_key(&self.genesis, order);
    let mut local_quantity =
      self.db.get(&local_key).map_or(0, |bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
    let on_chain_key = Self::on_chain_provided_quantity_key(&self.genesis, order);
    let on_chain_quantity =
      self.db.get(on_chain_key).map_or(0, |bytes| u32::from_le_bytes(bytes.try_into().unwrap()));

    let current_provided_key = self.current_provided_key();

    // This would have a race-condition with multiple calls to provide, though this takes &mut self
    // peventing multiple calls at once
    let mut txn = self.db.txn();
    txn.put(provided_key, tx.serialize());

    let this_provided_id = local_quantity;

    local_quantity += 1;
    txn.put(local_key, local_quantity.to_le_bytes());

    if this_provided_id < on_chain_quantity {
      // Verify against the on-chain version
      if tx_hash.as_ref() !=
        txn.get(Self::on_chain_provided_key(&self.genesis, order, this_provided_id)).unwrap()
      {
        Err(ProvidedError::LocalMismatchesOnChain)?;
      }
      txn.commit();
    } else {
      let mut currently_provided = txn.get(&current_provided_key).unwrap_or(vec![]);
      currently_provided.extend(tx_hash);
      txn.put(current_provided_key, currently_provided);
      txn.commit();

      if !self.transactions.contains_key(order) {
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
    block: [u8; 32],
    tx: [u8; 32],
  ) {
    if let Some(next_tx) = self.transactions.get_mut(order).and_then(VecDeque::pop_front) {
      assert_eq!(next_tx.hash(), tx);

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
    let on_chain_key = Self::on_chain_provided_quantity_key(&self.genesis, order);
    let block_order_key = Self::block_provided_quantity_key(&self.genesis, &block, order);
    let mut on_chain_quantity =
      self.db.get(&on_chain_key).map_or(0, |bytes| u32::from_le_bytes(bytes.try_into().unwrap()));

    let this_provided_id = on_chain_quantity;
    txn.put(Self::on_chain_provided_key(&self.genesis, order, this_provided_id), tx);

    on_chain_quantity += 1;
    txn.put(on_chain_key, on_chain_quantity.to_le_bytes());
    txn.put(block_order_key, on_chain_quantity.to_le_bytes());
  }
}
