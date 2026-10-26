use core::{marker::PhantomData, time::Duration};
use alloc::{
  vec::Vec,
  collections::{VecDeque, BTreeMap},
};
use std::time::Instant;

use serai_db::{Get, Transaction as DbTxn};

use crate::{
  ReadWrite,
  transaction::{TransactionKind, Transaction},
  Block,
};

use super::MempoolError;

serai_db::schema!(TributaryProvided {
  LocallyProvided: (genesis: [u8; 32], scope: &'static [u8]) -> u64,
  LocallyProvidedHash: (genesis: [u8; 32], scope: &'static [u8], index: u64) -> [u8; 32],
  LocallyProvidedTransaction: <T: ReadWrite>(
    genesis: [u8; 32], hash: [u8; 32]
  ) -> crate::ReadWriteAsBorsh<T>,
  Mempool: (genesis: [u8; 32]) -> Vec<[u8; 32]>,

  OnChainProvided: (genesis: [u8; 32], scope: &'static [u8]) -> u64,
  OnChainProvidedTransaction: <T: ReadWrite>(
    genesis: [u8; 32], scope: &'static [u8], index: u64
  ) -> crate::ReadWriteAsBorsh<T>,
});

/// The mempool and view over the provided transactions.
pub(super) struct Provided<T> {
  genesis: [u8; 32],
  transactions: BTreeMap<&'static [u8], VecDeque<(Instant, T)>>,
}

impl<T: Transaction> Provided<T> {
  /// Instance the mempool/view over provided transactions.
  pub(super) fn new(getter: &impl Get, genesis: [u8; 32]) -> Self {
    let mut transactions = BTreeMap::new();

    for hash in Mempool::get(getter, genesis).unwrap_or_else(Vec::new) {
      let transaction = LocallyProvidedTransaction::<T>::get(getter, genesis, hash)
        .expect("transaction in mempool wasn't saved to disk")
        .0;

      let TransactionKind::Provided { scope } = transaction.kind() else {
        panic!("provided transaction saved to the database wasn't a provided transaction");
      };
      let scope = scope.as_bytes();

      transactions
        .entry(scope)
        .or_insert_with(VecDeque::new)
        .push_back((Instant::now(), transaction));
    }

    Provided { genesis, transactions }
  }

  /// Create an iterator over the transactions to include in a block proposal.
  ///
  /// The transactions will be sorted according to the requirements for a block's syntactic
  /// validity. This will only yield the transactions which can be included on-chain within a
  /// single block.
  ///
  /// This only includes the provided transactions which have been in the mempool for at least one
  /// minute. This intends to ensure everyone has time to provide the transaction, preventing a
  /// block proposal from not being voted for solely due to minor timing differences with providing
  /// transactions.
  ///
  /// The caller is expected to apply the block's size limit.
  pub(super) fn block_proposal(&self) -> impl Iterator<Item = &T> {
    self.transactions.values().flatten().filter_map(|(time_added, transaction)| {
      (time_added.elapsed() >= Duration::from_mins(1)).then_some(transaction)
    })
  }

  /// Provide a provided transaction for inclusion on the blockchain.
  ///
  /// This will be appended to the queue for its scope if a transaction with this hash has not
  /// already been provided.
  ///
  /// Every participant is expected to be provide every provided transaction, in the exact same
  /// order. If a provided transaction exists on-chain, and has the index which the local view
  /// would assign to this transaction, the two will be checked to be equivalent. When a provided
  /// transaction is present in a block proposal, this validator will only vote for the proposal if
  /// a provided transaction with the same index is present in the local view and the two have the
  /// some hash.
  ///
  /// If a block is finalized, it will be appended to the Tributary
  /// _regardless of conflicts with the local view of provided transactions_. The application MUST
  /// confirm that the provided transactions included on-chain are equal to those provided by the
  /// local view.
  pub(super) fn provide(
    &mut self,
    txn: &mut impl DbTxn,
    transaction: T,
  ) -> Result<(), MempoolError> {
    let TransactionKind::Provided { scope } = transaction.kind() else {
      panic!("non-Provided transaction passed to `Provided::provide`")
    };
    let scope = scope.as_bytes();

    let () = crate::transaction::verify_syntax(&transaction, self.genesis)?;
    let hash = transaction.hash();

    // Check this hasn't already been provided
    if LocallyProvidedTransaction::<T>::get(txn, self.genesis, hash).is_some() {
      Err(MempoolError::AlreadyPresent)?;
    }

    // Assign this the next index within its scope (the scope's current amount of entries)
    let local_quantity = LocallyProvided::get(txn, self.genesis, scope).unwrap_or(0);
    let index = local_quantity;

    // If this has yet to appear on-chain, populate it into our mempool
    let add_to_mempool = {
      let on_chain_quantity = OnChainProvided::get(txn, self.genesis, scope).unwrap_or(0);
      if index < on_chain_quantity {
        let transaction = OnChainProvidedTransaction::<T>::get(txn, self.genesis, scope, index)
          .expect("on-chain provided transaction wasn't saved to disk")
          .0;

        if transaction.hash() != hash {
          Err(MempoolError::Conflict)?;
        }

        false
      } else {
        true
      }
    };

    LocallyProvidedTransaction::<T>::set(txn, self.genesis, hash, (&transaction).into());
    LocallyProvidedHash::set(txn, self.genesis, scope, local_quantity, &hash);
    LocallyProvided::set(txn, self.genesis, scope, &(local_quantity + 1));
    if add_to_mempool {
      let mut mempool = Mempool::get(txn, self.genesis).unwrap_or_else(|| Vec::with_capacity(1));
      mempool.push(hash);
      Mempool::set(txn, self.genesis, &mempool);

      self
        .transactions
        .entry(scope)
        .or_insert_with(VecDeque::new)
        .push_back((Instant::now(), transaction));
    }

    Ok(())
  }

  /// Handle an addition of a block to the blockchain.
  ///
  /// This included transactions will no longer be included within the mempool.
  ///
  /// If a validator was slashed, they will no longer be included by this mempool.
  ///
  /// This MUST only be called upon addition of a block verified to be valid, in the order seen
  /// on-chain.
  pub(super) fn block(&mut self, txn: &mut impl DbTxn, block: &Block<T>) {
    for transaction in block.transactions() {
      let TransactionKind::Provided { scope } = transaction.kind() else { continue };
      let scope = scope.as_bytes();

      let index = OnChainProvided::get(txn, self.genesis, scope).unwrap_or(0);
      OnChainProvided::set(txn, self.genesis, scope, &(index + 1));
      OnChainProvidedTransaction::<T>::set(txn, self.genesis, scope, index, transaction.into());

      let Some(scope_mempool) = self.transactions.get_mut(scope) else { continue };
      let mut local_index = LocallyProvided::get(txn, self.genesis, scope).unwrap_or(0) -
        u64::try_from(scope_mempool.len()).unwrap();
      let on_chain_quantity = OnChainProvided::get(txn, self.genesis, scope).unwrap_or(0);
      while local_index < on_chain_quantity {
        let Some((_time_added, local)) = scope_mempool.pop_front() else {
          /*
            We do not remove the scope's entry in the map even if its mempool is now empty. While
            this would premise a memleak, the scope is defined to be statically-allocated, so the
            creation of enough scopes to effect a memleak is inherently a memleak of its own and
            this is not _our_ problem.
          */
          break;
        };
        let local = local.hash();

        let mut mempool = Mempool::get(txn, self.genesis)
          .expect("locally provided transaction but no mempool saved to disk");
        let i = mempool
          .iter()
          .position(|hash| *hash == local)
          .expect("locally provided transaction wasn't in within our mempool");
        mempool.remove(i);
        Mempool::set(txn, self.genesis, &mempool);

        local_index += 1;
      }
    }
  }
}

pub(crate) struct ProvidedReader<T>(PhantomData<T>);
impl<T: Transaction> ProvidedReader<T> {
  /// Fetch the locally provided transactions within a scope.
  pub(crate) fn locally_provided(
    getter: &impl Get,
    genesis: [u8; 32],
    scope: &'static str,
    start: u64,
  ) -> impl Iterator<Item = [u8; 32]> {
    let scope = scope.as_bytes();
    (start .. LocallyProvided::get(getter, genesis, scope).unwrap_or(0)).map(move |i| {
      LocallyProvidedHash::get(getter, genesis, scope, i)
        .expect("locally provided transaction lacked `(scope, index) -> hash` index")
    })
  }
}
