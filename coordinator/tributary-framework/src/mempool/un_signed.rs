use alloc::{
  vec::Vec,
  collections::{VecDeque, BTreeMap},
};

use serai_db::{Get, Transaction as DbTxn};

use crate::{
  transaction::{TransactionError, Signed, TransactionKind, Transaction},
  Block,
};

use super::MempoolError;

mod db {
  use crate::{ReadWrite, ReadWriteAsBorsh};
  use super::*;

  serai_db::schema!(TributaryUnSigned {
    Censured: (genesis: [u8; 32], validator: [u8; 32]) -> (),
    Transaction: <T: ReadWrite>(genesis: [u8; 32], hash: [u8; 32]) -> ReadWriteAsBorsh<T>,
    Transactions: (genesis: [u8; 32]) -> Vec<[u8; 32]>,

    UnsignedOnChain: (genesis: [u8; 32], hash: [u8; 32]) -> (),
    SignedOnChain: (genesis: [u8; 32], signer: [u8; 32], scope: &[u8], nonce: u64) -> [u8; 32],
  });
}

struct ScopeMempool<T> {
  have_prior_on_chain: bool,
  transactions: VecDeque<T>,
}

type SignerMempool<T> = BTreeMap<Vec<u8>, ScopeMempool<T>>;

/// The (un)signed mempool and view over it.
pub(super) struct UnSigned<T> {
  genesis: [u8; 32],

  rate_limit: usize,

  /// The mempool for unsigned transactions.
  ///
  /// This can also be considered a `BTreeSet<T>` where `<T as core::cmp::Ord>` is implemented by
  /// deferring to `<<T as Transaction>::hash() as core::cmp::Ord>`.
  unsigned: BTreeMap<[u8; 32], T>,

  /// The mempool for signed transactions.
  ///
  /// This is indexed as `signer -> scope -> transactions`.
  ///
  /// When this mempool is instanced, it's populated with all validators, causing the presence of
  /// an entry in the signed mempool to be equivalent to if the signer is a validator or not.
  signed: BTreeMap<[u8; 32], SignerMempool<T>>,
}

impl<T: Transaction> UnSigned<T> {
  /// If a validator has been censured.
  #[must_use]
  pub(super) fn censured(getter: &impl Get, genesis: [u8; 32], validator: [u8; 32]) -> bool {
    db::Censured::get(getter, genesis, validator).is_some()
  }

  /// Instance the mempool for this blockchain.
  ///
  /// When a transaction is added to the mempool, `rate_limit` configures the amount of
  /// transactions a validator may have already pending within the mempool in order for the mempool
  /// to not return `Err(MempoolError::RateLimit)`. Note this rate limiting may be explicitly
  /// bypassed (as suggested for a validator's own transactions) and is not considered when
  /// reloading the mempool from the database.
  pub(super) fn new(
    txn: &mut impl DbTxn,
    genesis: [u8; 32],
    validators: impl IntoIterator<Item = [u8; 32]>,
    rate_limit: usize,
  ) -> Self {
    let mut unsigned = BTreeMap::new();
    let mut signed = validators
      .into_iter()
      .filter(|signer| db::Censured::get(txn, genesis, *signer).is_none())
      .map(|signer| (signer, BTreeMap::new()))
      .collect::<BTreeMap<[u8; 32], SignerMempool<T>>>();

    for hash in db::Transactions::get(txn, genesis).into_iter().flatten() {
      let transaction = db::Transaction::<T>::get(txn, genesis, hash)
        .expect("transaction in mempool wasn't saved to disk")
        .0;

      match transaction.kind() {
        TransactionKind::Provided { .. } => panic!("provided transaction added to the mempool"),
        TransactionKind::Unsigned => {
          unsigned.insert(transaction.hash(), transaction);
        }
        TransactionKind::Signed { scope, signed: Signed { signer, nonce, signature: _ } } => {
          let Some(signer_mempool) = signed.get_mut(&signer) else {
            db::Transaction::<T>::del(txn, genesis, transaction.hash());
            continue;
          };
          signer_mempool
            .entry(scope)
            .or_insert_with_key(|scope| ScopeMempool {
              have_prior_on_chain: nonce.checked_sub(1).is_none_or(|prior_nonce| {
                db::SignedOnChain::get(txn, genesis, signer, scope, prior_nonce).is_some()
              }),
              transactions: VecDeque::new(),
            })
            .transactions
            .push_back(transaction);
        }
      }
    }

    let mut result = UnSigned { genesis, rate_limit, unsigned, signed };
    result.save(txn);
    result
  }

  /// An iterator over all transactions in the mempool.
  fn iter(&self, filter_without_prior_on_chain: bool) -> impl Iterator<Item = &T> {
    #[expect(clippy::iter_kv_map)]
    self.unsigned.values().chain(self.signed.iter().flat_map(move |(_signer, signer_mempool)| {
      signer_mempool
        .iter()
        .filter_map(move |(_scope, scope_mempool)| {
          ((!filter_without_prior_on_chain) || scope_mempool.have_prior_on_chain)
            .then_some(&scope_mempool.transactions)
        })
        .flatten()
    }))
  }

  /// Save the mempool to the database.
  fn save(&mut self, txn: &mut impl DbTxn) {
    let mempool = self.iter(false).map(Transaction::hash).collect();
    db::Transactions::set(txn, self.genesis, &mempool);
  }

  /// Find a transaction in a signer's mempool which cannot be published at this time.
  ///
  /// This will return a mutable reference to the relevant scope's mempool. This function will not
  /// perform any mutations itself though.
  fn find_unpublishable_transaction(
    signer_mempool: &mut SignerMempool<T>,
  ) -> Option<&mut ScopeMempool<T>> {
    for scope_mempool in signer_mempool.values_mut() {
      // Transactions for which there is a gap between the mempool and the on-chain state
      if !scope_mempool.have_prior_on_chain {
        return Some(scope_mempool);
      }

      // Transactions for which there is a gap within the mempool
      let transactions = &scope_mempool.transactions;
      if transactions.len() > 1 {
        let TransactionKind::Signed { scope: _, signed: Signed { nonce: first, .. } } =
          transactions.front().unwrap().kind()
        else {
          panic!("non-signed transaction in signer's mempool");
        };
        let TransactionKind::Signed { scope: _, signed: Signed { nonce: last, .. } } =
          transactions.back().unwrap().kind()
        else {
          panic!("non-signed transaction in signer's mempool");
        };

        if if let Ok(expected_len_minus_one) = usize::try_from(last - first) {
          expected_len_minus_one != (transactions.len() - 1)
        } else {
          /*
            If the expected length isn't even representable as a `usize`, then our mempool
            (stored in memory, bound by the limitations of `usize`) definitely cannot be without
            gaps.
          */
          true
        } {
          return Some(scope_mempool);
        }
      }
    }

    None
  }

  /// Add a transaction to the mempool.
  ///
  /// This will panic if the transaction is a provided transaction.
  pub(super) fn add(
    &mut self,
    txn: &mut impl DbTxn,
    transaction: T,
    bypass_rate_limit: bool,
  ) -> Result<(), MempoolError> {
    let hash = transaction.hash();

    let mut prune = None;
    let transaction: &T = match transaction.kind() {
      TransactionKind::Provided { .. } => panic!("provided transaction being added to the mempool"),
      TransactionKind::Unsigned => {
        crate::transaction::verify_syntax(&transaction, self.genesis)?;

        if db::UnsignedOnChain::get(txn, self.genesis, hash).is_some() {
          Err(MempoolError::AlreadyPresent)?;
        }

        let entry = self.unsigned.entry(hash);
        if matches!(entry, alloc::collections::btree_map::Entry::Occupied(_)) {
          Err(MempoolError::AlreadyPresent)?;
        }
        &*entry.insert_entry(transaction).into_mut()
      }
      TransactionKind::Signed { scope, signed: Signed { signer, nonce, signature: _ } } => {
        crate::transaction::verify_syntax(&transaction, self.genesis)?;

        if let Some(on_chain) = db::SignedOnChain::get(txn, self.genesis, signer, &scope, nonce) {
          if on_chain == hash {
            Err(MempoolError::AlreadyPresent)?;
          } else {
            Err(MempoolError::Conflict)?;
          }
        }

        let signer_mempool = self
          .signed
          .get_mut(&signer)
          .ok_or(MempoolError::Invalid(TransactionError::InvalidSigner))?;

        if !bypass_rate_limit {
          // Check this signer's mempool isn't larger than the rate limit
          let Some(rate) = signer_mempool
            .values()
            .map(|scope_mempool| scope_mempool.transactions.len())
            .try_fold(0usize, usize::checked_add)
          else {
            Err(MempoolError::RateLimit)?
          };
          if rate > self.rate_limit {
            Err(MempoolError::RateLimit)?;
          }

          /*
            If this signer's mempool is at the rate limit, we still allow this transaction to be
            added immediately. However, we flag that this signer's mempool should be pruned. The
            pruning operation will prefer a transaction which cannot be published at this time.

            This ensures that if a signer's mempool is full of transactions which cannot currently
            be published, their mempool doesn't stall and transactions which can be published will
            still be included.
          */
          prune = (rate == self.rate_limit).then_some(signer);
        }

        let scope_mempool_entry = match signer_mempool.entry(scope) {
          alloc::collections::btree_map::Entry::Occupied(entry) => entry,
          alloc::collections::btree_map::Entry::Vacant(entry) => entry.insert_entry(ScopeMempool {
            have_prior_on_chain: false,
            transactions: VecDeque::new(),
          }),
        };
        let scope_mempool = scope_mempool_entry.get();

        match scope_mempool.transactions.binary_search_by_key(&nonce, |transaction_in_mempool| {
          match transaction_in_mempool.kind() {
            TransactionKind::Signed {
              scope: _,
              signed: Signed { signer: signer_in_mempool, nonce, signature: _ },
            } => {
              assert_eq!(
                signer_in_mempool, signer,
                "signer of transaction in signer's mempool distinct from signer"
              );
              nonce
            }
            TransactionKind::Provided { .. } | TransactionKind::Unsigned => {
              panic!("non-signed transaction in mempool's signed transactions")
            }
          }
        }) {
          Ok(i) => {
            if scope_mempool.transactions[i].hash() == hash {
              Err(MempoolError::AlreadyPresent)?;
            }
            Err(MempoolError::Conflict)?
          }
          Err(i) => {
            // If we're inserting into the first position, update `have_prior_on_chain`
            let have_prior_on_chain = if i == 0 {
              nonce.checked_sub(1).is_none_or(|prior_nonce| {
                db::SignedOnChain::get(
                  txn,
                  self.genesis,
                  signer,
                  scope_mempool_entry.key(),
                  prior_nonce,
                )
                .is_some()
              })
            } else {
              // If we're not inserting into the first position, this is unchanged
              scope_mempool.have_prior_on_chain
            };
            let scope_mempool = scope_mempool_entry.into_mut();
            scope_mempool.have_prior_on_chain = have_prior_on_chain;
            &*scope_mempool.transactions.insert_mut(i, transaction)
          }
        }
      }
    };

    db::Transaction::<T>::set(txn, self.genesis, hash, transaction.into());

    let prune_result = if let Some(signer) = prune {
      /*
        Get the scope of the added transaction.

        If we are unable to find an unpublishable transaction, we will fallback to pruning a
        transaction from this scope. The pruned transaction will either be the transaction we just
        added _or_ a transaction in the same scope, but with a later nonce, if the transaction we
        just added filled a gap. This means we either remove the transaction we just added, as if
        we refused it due to the rate limit, _or_ we have achieved a strict improvement over the
        prior mempool.

        Unfortunately, because the `transaction` variable holds a borrow over the mempool, we need
        to fetch its scope now, before dropping the reference in order to search for unpublishable
        transactions.
      */
      let scope_of_added_transaction = {
        let TransactionKind::Signed { scope, signed: _ } = transaction.kind() else {
          panic!("pruning a signer's mempool but not adding a signed transaction")
        };
        scope
      };

      let signer_mempool =
        self.signed.get_mut(&signer).expect("pruning a signer's mempool we don't have");
      let scope_mempool = match Self::find_unpublishable_transaction(signer_mempool) {
        Some(scope_mempool) => scope_mempool,
        None => signer_mempool
          .get_mut(&scope_of_added_transaction)
          .expect("added a transaction but its scope doesn't exist within the signer's mempool"),
      };
      let transaction = scope_mempool
        .transactions
        .pop_back()
        .expect("pruning from a scope in a signer's mempool which is empty");
      let TransactionKind::Signed { scope, signed: _ } = transaction.kind() else {
        panic!("pruning a transaction from a signer's mempool but it wasn't a signed transaction")
      };
      let pruned_hash = transaction.hash();
      db::Transaction::<T>::del(txn, self.genesis, pruned_hash);

      if scope_mempool.transactions.is_empty() {
        signer_mempool.remove(&scope);
      }

      (hash != pruned_hash).ok_or(MempoolError::RateLimit)
    } else {
      Ok(())
    };

    self.save(txn);

    prune_result
  }

  /// Create an iterator over the transactions to include in a block proposal.
  ///
  /// The transactions will be sorted according to the requirements for a block's syntactic
  /// validity. This will only yield the transactions which can be included on-chain within a
  /// single block.
  ///
  /// The caller is expected to apply the block's size limit.
  pub(super) fn block_proposal(&self) -> impl Iterator<Item = &T> {
    struct Filter<'mempool, T: 'mempool, I: Iterator<Item = &'mempool T>> {
      last: Option<([u8; 32], Vec<u8>, u64)>,
      signer_size: usize,
      iter: I,
    }
    impl<'mempool, T: 'mempool + Transaction, I: Iterator<Item = &'mempool T>> Iterator
      for Filter<'mempool, T, I>
    {
      type Item = &'mempool T;
      fn next(&mut self) -> Option<Self::Item> {
        loop {
          let next_transaction = self.iter.next()?;
          match next_transaction.kind() {
            TransactionKind::Signed { scope, signed: Signed { signer, nonce, signature: _ } } => {
              // If we're within the same signer and scope, check this is contiguous
              if self.last.as_ref().is_some_and(|(last_signer, last_scope, last_nonce)| {
                (last_signer == &signer) &&
                  (last_scope == &scope) &&
                  (Some(*last_nonce) != nonce.checked_sub(1))
              }) {
                continue;
              }

              // If this is a new signer, clear the signer's size
              if self
                .last
                .as_ref()
                .is_some_and(|(last_signer, _last_scope, _last_nonce)| last_signer != &signer)
              {
                self.signer_size = 0;
              }

              /*
                While the caller is expected to apply the block's size limit, we still apply the
                block's size limit _to individual signers_. This lets the caller choose how to
                prefer transactions between signers, without providing transactions which
                definitely won't be included.

                There is a slight caveat, as a later scope of a signer could be preferred over an
                earlier scope, but that isn't modelled here.
              */
              let Some(new_size) = self.signer_size.checked_add({
                let Ok(size) = crate::serialized_len(next_transaction) else { continue };
                size
              }) else {
                continue;
              };
              if let Some(block_size_limit) = T::BLOCK_SIZE_LIMIT &&
                (new_size > block_size_limit)
              {
                continue;
              }

              self.last = Some((signer, scope, nonce));
              self.signer_size = new_size;
              return Some(next_transaction);
            }
            TransactionKind::Provided { .. } | TransactionKind::Unsigned => {
              return Some(next_transaction);
            }
          }
        }
      }
    }
    Filter { last: None, signer_size: 0, iter: self.iter(true) }
  }

  /// Censure a validator.
  pub(super) fn censure(&mut self, txn: &mut impl DbTxn, validator: [u8; 32]) {
    db::Censured::set(txn, self.genesis, validator, &());
    for transaction in self
      .signed
      .remove(&validator)
      .into_iter()
      .flatten()
      .flat_map(|(_scope, scope_mempool)| scope_mempool.transactions)
    {
      db::Transaction::<T>::del(txn, self.genesis, transaction.hash());
    }
    self.save(txn);
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
    for slash in block.slashes() {
      self.censure(txn, *slash.validator());
    }

    for transaction in block.transactions() {
      match transaction.kind() {
        TransactionKind::Provided { .. } => continue,
        TransactionKind::Unsigned => {
          let hash = transaction.hash();
          db::UnsignedOnChain::set(txn, self.genesis, hash, &());

          self.unsigned.remove(&hash);
          db::Transaction::<T>::del(txn, self.genesis, hash);
        }
        TransactionKind::Signed { scope, signed: Signed { signer, nonce, signature: _ } } => {
          db::SignedOnChain::set(txn, self.genesis, signer, &scope, nonce, &transaction.hash());

          if let Some(signer_mempool) = self.signed.get_mut(&signer) &&
            let Some(scope_mempool) = signer_mempool.get_mut(&scope)
          {
            while scope_mempool.transactions.front().is_some_and(|transaction| {
              match transaction.kind() {
                TransactionKind::Signed {
                  scope: _,
                  signed: Signed { signer: _, nonce: nonce_in_scope, signature: _ },
                } => nonce_in_scope <= nonce,
                TransactionKind::Provided { .. } | TransactionKind::Unsigned => {
                  panic!("non-signed transaction added to signed transactions in mempool")
                }
              }
            }) {
              db::Transaction::<T>::del(
                txn,
                self.genesis,
                scope_mempool.transactions.pop_front().unwrap().hash(),
              );
            }
            if let Some(first) = scope_mempool.transactions.front() {
              let TransactionKind::Signed {
                scope: _,
                signed: Signed { signer: _, nonce, signature: _ },
              } = first.kind()
              else {
                panic!("non-signed transaction added to signed transactions in mempool")
              };
              scope_mempool.have_prior_on_chain = nonce.checked_sub(1).is_none_or(|prior_nonce| {
                db::SignedOnChain::get(txn, self.genesis, signer, &scope, prior_nonce).is_some()
              });
            } else {
              signer_mempool.remove(&scope);
            }
          }
        }
      }
    }

    self.save(txn);
  }
}
