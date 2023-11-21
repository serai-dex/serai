use std::collections::{VecDeque, HashMap};

use thiserror::Error;

use serai_db::{Get, DbTxn, Db, create_db};
use scale::Encode;
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

create_db!(
  TributaryProvidedDb {
    TransactionDb: (genesis: &[u8], hash: &[u8]) -> Vec<u8>,
    CurrentDb: (genesis: &[u8]) -> Vec<u8>,
    LocalQuantityDb: (genesis: &[u8], order: &[u8]) -> u32,
    OnChainQuantityDb: (genesis: &[u8], order: &[u8]) -> u32,
    BlockQuantityDb: (genesis: &[u8], block: &[u8], order: &[u8]) -> u32,
    OnChainTxDb: (genesis: &[u8], order: &[u8], id: u32) -> [u8; 32]
  }
);

impl<D: Db, T: Transaction> ProvidedTransactions<D, T> {
  pub(crate) fn new(db: D, genesis: [u8; 32]) -> Self {
    let mut res = ProvidedTransactions { db, genesis, transactions: HashMap::new() };
    let currently_provided = CurrentDb::get(&res.db, &genesis).unwrap_or_default();
    let mut i = 0;
    while i < currently_provided.len() {
      let tx = T::read::<&[u8]>(
        &mut TransactionDb::get(&res.db, &res.genesis, &currently_provided[i .. (i + 32)])
          .unwrap()
          .as_ref(),
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

    // Check it wasn't already provided
    if TransactionDb::get(&self.db, &self.genesis, &tx_hash).is_some() {
      Err(ProvidedError::AlreadyProvided)?;
    }

    // get local and on-chain tx numbers
    let order_bytes = order.as_bytes();
    let mut local_quantity =
      LocalQuantityDb::get(&self.db, &self.genesis, order_bytes).unwrap_or_default();
    let on_chain_quantity =
      OnChainQuantityDb::get(&self.db, &self.genesis, order_bytes).unwrap_or_default();

    // This would have a race-condition with multiple calls to provide, though this takes &mut self
    // peventing multiple calls at once
    let mut txn = self.db.txn();
    TransactionDb::set(&mut txn, &self.genesis, &tx_hash, &tx.serialize());

    let this_provided_id = local_quantity;

    local_quantity += 1;
    LocalQuantityDb::set(&mut txn, &self.genesis, order_bytes, &local_quantity);

    if this_provided_id < on_chain_quantity {
      // Verify against the on-chain version
      if tx_hash.as_ref() !=
        OnChainTxDb::get(&txn, &self.genesis, order_bytes, this_provided_id).unwrap()
      {
        Err(ProvidedError::LocalMismatchesOnChain)?;
      }
      txn.commit();
    } else {
      #[allow(clippy::unwrap_or_default)]
      let mut currently_provided = CurrentDb::get(&txn, &self.genesis).unwrap_or_default();
      currently_provided.extend(tx_hash);
      CurrentDb::set(&mut txn, &self.genesis, &currently_provided);
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
    block: [u8; 32],
    tx: [u8; 32],
  ) {
    if let Some(next_tx) = self.transactions.get_mut(order).and_then(|queue| queue.pop_front()) {
      assert_eq!(next_tx.hash(), tx);
      let mut currently_provided = CurrentDb::get(txn, &self.genesis).unwrap();

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
      CurrentDb::set(txn, &self.genesis, &currently_provided);
    }

    // bump the on-chain tx number.
    let order_bytes = order.as_bytes();
    let mut on_chain_quantity =
      OnChainQuantityDb::get(&self.db, &self.genesis, order_bytes).unwrap_or_default();
    let this_provided_id = on_chain_quantity;

    //    let block_order_key = Self::block_provided_quantity_key(&self.genesis, &block, order);

    OnChainTxDb::set(txn, &self.genesis, order_bytes, this_provided_id, &tx);

    on_chain_quantity += 1;
    OnChainQuantityDb::set(txn, &self.genesis, order_bytes, &on_chain_quantity);
    BlockQuantityDb::set(txn, &self.genesis, &block, order_bytes, &on_chain_quantity);
  }
}
