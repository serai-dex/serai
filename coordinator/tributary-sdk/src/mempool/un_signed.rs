use alloc::{
  vec::Vec,
  collections::{VecDeque, BTreeMap},
};

use serai_db::{Get, Transaction as DbTxn};

use crate::{
  transaction::{Signed, TransactionKind, Transaction},
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

type SignerMempool<T> = BTreeMap<Vec<u8>, VecDeque<T>>;

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
        TransactionKind::Signed { scope, signed: Signed { signer, .. } } => {
          let Some(signer_mempool) = signed.get_mut(&signer) else {
            db::Transaction::<T>::del(txn, genesis, transaction.hash());
            continue;
          };
          signer_mempool.entry(scope).or_insert_with(VecDeque::new).push_back(transaction);
        }
      }
    }

    let mut result = UnSigned { genesis, rate_limit, unsigned, signed };
    result.save(txn);
    result
  }

  /// An iterator over all transactions in the mempool.
  fn iter(&self) -> impl Iterator<Item = &T> {
    #[expect(clippy::iter_kv_map)]
    self.unsigned.values().chain(self.signed.iter().flat_map(|(_signer, signer_mempool)| {
      signer_mempool.iter().flat_map(|(_scope, transactions)| transactions)
    }))
  }

  /// Save the mempool to the database.
  fn save(&mut self, txn: &mut impl DbTxn) {
    let mempool = self.iter().map(Transaction::hash).collect();
    db::Transactions::set(txn, self.genesis, &mempool);
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

        let signer_mempool = self.signed.get_mut(&signer).ok_or(MempoolError::InvalidSigner)?;
        if (!bypass_rate_limit) &&
          signer_mempool
            .values()
            .map(VecDeque::len)
            .try_fold(0usize, usize::checked_add)
            .is_none_or(|pending| pending >= self.rate_limit)
        {
          // TODO: If this transaction can be published _now_, supplant a transaction which can't
          // be published _now_
          Err(MempoolError::RateLimit)?;
        }
        let scope_mempool = signer_mempool.entry(scope).or_insert_with(VecDeque::new);
        match scope_mempool.binary_search_by_key(&nonce, |transaction_in_mempool| {
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
            if scope_mempool[i].hash() == hash {
              Err(MempoolError::AlreadyPresent)?;
            }
            Err(MempoolError::Conflict)?
          }
          Err(i) => &*scope_mempool.insert_mut(i, transaction),
        }
      }
    };

    db::Transaction::<T>::set(txn, self.genesis, hash, transaction.into());
    self.save(txn);

    Ok(())
  }

  /// Create an iterator over the transactions to include in a block proposal.
  ///
  /// The transactions will be sorted according to the requirements for a block's syntactic
  /// validity. This will only yield the transactions which can be included on-chain within a
  /// single block.
  ///
  /// The caller is expected to apply the block's size limit.
  pub(super) fn block_proposal<'mempool>(
    &'mempool self,
    getter: &'mempool impl Get,
  ) -> impl Iterator<Item = &'mempool T> {
    struct Filter<'mempool, G: Get, T: 'mempool, I: Iterator<Item = &'mempool T>> {
      getter: &'mempool G,
      genesis: [u8; 32],
      last: Option<([u8; 32], Vec<u8>, u64)>,
      iter: I,
    }
    impl<'mempool, G: 'mempool + Get, T: 'mempool + Transaction, I: Iterator<Item = &'mempool T>>
      Iterator for Filter<'mempool, G, T, I>
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

              // If we're entering a new signer/scope, check this is ready to be included on-chain
              if self.last.as_ref().is_none_or(|(last_signer, last_scope, _last_nonce)| {
                (last_signer, last_scope) != (&signer, &scope)
              }) && let Some(prior_nonce) = nonce.checked_sub(1) &&
                db::SignedOnChain::get(self.getter, self.genesis, signer, &scope, prior_nonce)
                  .is_none()
              {
                continue;
              }

              self.last = Some((signer, scope, nonce));
              return Some(next_transaction);
            }
            TransactionKind::Provided { .. } | TransactionKind::Unsigned => {
              return Some(next_transaction);
            }
          }
        }
      }
    }
    Filter { getter, genesis: self.genesis, last: None, iter: self.iter() }
  }

  /// Censure a validator.
  pub(super) fn censure(&mut self, txn: &mut impl DbTxn, validator: [u8; 32]) {
    db::Censured::set(txn, self.genesis, validator, &());
    for transaction in self
      .signed
      .remove(&validator)
      .into_iter()
      .flatten()
      .flat_map(|(_scope, transactions)| transactions)
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
            let Some(in_scope) = signer_mempool.get_mut(&scope)
          {
            while in_scope.front().is_some_and(|transaction| match transaction.kind() {
              TransactionKind::Signed {
                scope: scope_in_scope,
                signed: Signed { signer: signer_in_scope, nonce: nonce_in_scope, signature: _ },
              } => {
                assert_eq!(
                  scope_in_scope, scope,
                  "scope of transaction in scope's mempool distinct from scope"
                );
                assert_eq!(
                  signer_in_scope, signer,
                  "signer of transaction in signer's mempool distinct from signer"
                );
                nonce_in_scope <= nonce
              }
              TransactionKind::Provided { .. } | TransactionKind::Unsigned => {
                panic!("non-signed transaction added to signed transactions in mempool")
              }
            }) {
              db::Transaction::<T>::del(txn, self.genesis, in_scope.pop_front().unwrap().hash());
            }
            if in_scope.is_empty() {
              signer_mempool.remove(&scope);
            }
          }
        }
      }
    }

    self.save(txn);
  }
}
