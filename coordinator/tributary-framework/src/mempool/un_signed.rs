use alloc::{
  boxed::Box,
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

impl<T: Transaction> ScopeMempool<T> {
  fn iter_with_prior(&self) -> impl Iterator<Item = &T> {
    let mut last_nonce: Option<u64> = None;
    self.transactions.iter().filter(move |transaction| {
      let TransactionKind::Signed { scope: _, signed: Signed { nonce, .. } } = transaction.kind()
      else {
        panic!("non-signed transaction in signer's mempool")
      };

      if self.have_prior_on_chain &&
        last_nonce.is_none_or(|last_nonce| last_nonce.checked_add(1) == Some(nonce))
      {
        last_nonce = Some(nonce);
        true
      } else {
        false
      }
    })
  }
}

#[test]
fn iter_with_prior() {
  use crate::transaction::TestTransaction;
  let transaction = |nonce| TestTransaction {
    valid: true,
    kind: TransactionKind::Signed {
      scope: Box::default(),
      signed: Signed { signer: [0; 32], nonce, signature: [0; 64] },
    },
    salt: 0,
  };

  let transactions = (0 .. 5).map(transaction).collect::<Vec<_>>();
  assert_eq!(
    (ScopeMempool::<TestTransaction> {
      have_prior_on_chain: true,
      transactions: VecDeque::from([transactions[0].clone()])
    })
    .iter_with_prior()
    .map(Transaction::hash)
    .collect::<Vec<_>>(),
    [transactions[0].hash()]
  );
  assert_eq!(
    (ScopeMempool::<TestTransaction> {
      have_prior_on_chain: false,
      transactions: VecDeque::from([transactions[1].clone(), transactions[2].clone()])
    })
    .iter_with_prior()
    .map(Transaction::hash)
    .collect::<Vec<_>>(),
    <[[u8; 32]; 0]>::default()
  );
  assert_eq!(
    (ScopeMempool::<TestTransaction> {
      have_prior_on_chain: true,
      transactions: VecDeque::from([transactions[1].clone(), transactions[2].clone()])
    })
    .iter_with_prior()
    .map(Transaction::hash)
    .collect::<Vec<_>>(),
    [transactions[1].hash(), transactions[2].hash()]
  );
  assert_eq!(
    (ScopeMempool::<TestTransaction> {
      have_prior_on_chain: true,
      transactions: VecDeque::from([
        transactions[1].clone(),
        transactions[3].clone(),
        transactions[4].clone()
      ])
    })
    .iter_with_prior()
    .map(Transaction::hash)
    .collect::<Vec<_>>(),
    [transactions[1].hash()]
  );
}

struct PopUntil<'map, T> {
  scope_mempool_entry:
    alloc::collections::btree_map::OccupiedEntry<'map, Box<[u8]>, ScopeMempool<T>>,
  on_chain_nonce: u64,
}

impl<'map, T: Transaction> PopUntil<'map, T> {
  /// Pop all transactions up to and including the specified `on_chain_nonce`.
  ///
  /// `on_chain_nonce` MUST be the latest nonce seen on-chain within this signer's scope.
  ///
  /// This iterator MUST be exhausted.
  fn new(
    scope_mempool_entry: alloc::collections::btree_map::OccupiedEntry<
      'map,
      Box<[u8]>,
      ScopeMempool<T>,
    >,
    on_chain_nonce: u64,
  ) -> Self {
    Self { scope_mempool_entry, on_chain_nonce }
  }

  fn next(mut self) -> Option<(Self, T)> {
    let scope_mempool = self.scope_mempool_entry.get_mut();
    if let Some(transaction) =
      scope_mempool.transactions.pop_front_if(|transaction| match transaction.kind() {
        TransactionKind::Signed {
          scope: _,
          signed: Signed { signer: _, nonce: nonce_in_scope, signature: _ },
        } => nonce_in_scope <= self.on_chain_nonce,
        TransactionKind::Provided { .. } | TransactionKind::Unsigned => {
          panic!("non-signed transaction added to signed transactions in mempool")
        }
      })
    {
      return Some((self, transaction));
    }

    /*
      Now that we've removed all transactions up to and including the specified nonce, correct
      `have_prior_on_chain` which is dirtied whenever `transactions` is mutated.
    */
    if let Some(first) = scope_mempool.transactions.front() {
      let TransactionKind::Signed { scope: _, signed: Signed { signer: _, nonce, signature: _ } } =
        first.kind()
      else {
        panic!("non-signed transaction added to signed transactions in mempool")
      };
      scope_mempool.have_prior_on_chain =
        nonce.checked_sub(1).is_none_or(|prior_nonce| prior_nonce == self.on_chain_nonce);
    } else {
      /*
        Because this scope is now empty, remove it from the signer's mempool.

        Because we are dropping the `ScopeMempool` here, we do not have to set
        `have_prior_on_chain` to any value.
      */
      self.scope_mempool_entry.remove_entry();
    }

    None
  }
}

#[test]
fn pop_until() {
  use crate::transaction::TestTransaction;

  let transaction = |nonce| TestTransaction {
    valid: true,
    kind: TransactionKind::Signed {
      scope: Box::default(),
      signed: Signed { signer: [0; 32], nonce, signature: [0; 64] },
    },
    salt: 0,
  };

  let mut parent = BTreeMap::new();
  let two = transaction(2);
  let three = transaction(3);
  let five = transaction(5);

  for on_chain_nonce in [3, 4] {
    let scope_mempool_entry =
      parent.entry(Box::default()).insert_entry(ScopeMempool::<TestTransaction> {
        have_prior_on_chain: true,
        transactions: VecDeque::from([two.clone(), three.clone(), five.clone()]),
      });

    {
      let mut iter = PopUntil { scope_mempool_entry, on_chain_nonce };
      let mut removed = [two.clone(), three.clone()].into_iter();
      while let Some((returned_iter, transaction)) = iter.next() {
        iter = returned_iter;
        assert_eq!(transaction.hash(), removed.next().unwrap().hash());
      }
    }

    let scope_mempool = &parent[[].as_slice()];
    assert_eq!(
      scope_mempool.transactions.iter().map(Transaction::hash).collect::<Vec<_>>(),
      alloc::vec![five.hash()]
    );
    assert_eq!(scope_mempool.have_prior_on_chain, on_chain_nonce == 4);
  }
}

struct SignerMempool<T>(BTreeMap<Box<[u8]>, ScopeMempool<T>>);
impl<T: Transaction> SignerMempool<T> {
  fn new() -> Self {
    Self(BTreeMap::new())
  }

  /// The amount of transactions within this mempool.
  ///
  /// This is `None` on overflow.
  fn rate(&self) -> Option<usize> {
    self
      .0
      .values()
      .map(|scope_mempool| scope_mempool.transactions.len())
      .try_fold(0usize, usize::checked_add)
  }

  /// Find a transaction in a signer's mempool which cannot be published at this time.
  ///
  /// This will return a reference to the scope and a mutable reference to the relevant scope's
  /// mempool. This function will not perform any mutations itself though.
  #[expect(clippy::borrowed_box)]
  fn find_unpublishable_transaction(&mut self) -> Option<(&Box<[u8]>, &mut ScopeMempool<T>)> {
    for (scope, scope_mempool) in &mut self.0 {
      // Transactions for which there is a gap between the mempool and the on-chain state
      if !scope_mempool.have_prior_on_chain {
        return Some((scope, scope_mempool));
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
          return Some((scope, scope_mempool));
        }
      }
    }

    None
  }

  /// Add a transaction to this signer's mempool.
  ///
  /// This function maintains the signer's mempool by:
  /// - checking the transaction isn't already present within itself or on-chain
  /// - checking the transaction doesn't conflict with an existing transaction within itself or
  ///   on-chain
  /// - updating if this scope has the necessary prior transactions on-chain or not (a value cached
  ///   within each scope's mempool and dirtied upon any changes to the scope's transactions)
  ///
  /// This function DOES NOT check the transaction's validity, expected consistency with the
  /// surrounding values, or if any rate limits should apply. It MUST be used carefully.
  ///
  /// This returns a reference to the added transaction.
  #[expect(clippy::too_many_arguments)]
  fn add(
    &mut self,
    getter: &impl Get,
    genesis: [u8; 32],
    signer: [u8; 32],
    scope: Box<[u8]>,
    nonce: u64,
    hash: [u8; 32],
    transaction: T,
  ) -> Result<&T, MempoolError> {
    if let Some(on_chain) = db::SignedOnChain::get(getter, genesis, signer, &scope, nonce) {
      if on_chain == hash {
        Err(MempoolError::AlreadyPresent)?;
      } else {
        Err(MempoolError::Conflict)?;
      }
    }

    let scope_mempool_entry = match self.0.entry(scope) {
      alloc::collections::btree_map::Entry::Occupied(entry) => entry,
      alloc::collections::btree_map::Entry::Vacant(entry) => entry
        .insert_entry(ScopeMempool { have_prior_on_chain: false, transactions: VecDeque::new() }),
    };
    let scope_mempool = scope_mempool_entry.get();

    match scope_mempool.transactions.binary_search_by_key(&nonce, |transaction_in_mempool| {
      match transaction_in_mempool.kind() {
        TransactionKind::Signed { scope: _, signed: Signed { nonce, .. } } => nonce,
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
            db::SignedOnChain::get(getter, genesis, signer, scope_mempool_entry.key(), prior_nonce)
              .is_some()
          })
        } else {
          // If we're not inserting into the first position, this is unchanged
          scope_mempool.have_prior_on_chain
        };
        let scope_mempool = scope_mempool_entry.into_mut();
        scope_mempool.have_prior_on_chain = have_prior_on_chain;
        Ok(&*scope_mempool.transactions.insert_mut(i, transaction))
      }
    }
  }
}

#[test]
fn find_unpublishable_transaction() {
  use crate::transaction::TestTransaction;

  let genesis = [0xfe; 32];
  let signer = [0xaa; 32];

  let transaction = |nonce| TestTransaction {
    valid: true,
    kind: TransactionKind::Signed {
      scope: Box::default(),
      signed: Signed { signer, nonce, signature: [0; 64] },
    },
    salt: 0,
  };

  let mut signer_mempool = SignerMempool::new();
  let three = transaction(3);
  let four = transaction(4);
  let five = transaction(5);

  signer_mempool.0.insert(
    Box::default(),
    ScopeMempool::<TestTransaction> {
      have_prior_on_chain: true,
      transactions: VecDeque::from([three, five]),
    },
  );

  assert!(signer_mempool.find_unpublishable_transaction().is_some());
  signer_mempool
    .add(&serai_db::MemDb::new(), genesis, signer, Box::default(), 4, four.hash(), four)
    .unwrap();
  assert!(signer_mempool.find_unpublishable_transaction().is_none());

  signer_mempool.0.get_mut(&Box::default()).unwrap().have_prior_on_chain = false;
  assert!(signer_mempool.find_unpublishable_transaction().is_some());
}

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

  /// Save the mempool to the database.
  fn save(&mut self, txn: &mut impl DbTxn) {
    let mempool = self
      .unsigned
      .values()
      .chain(self.signed.values().flat_map(|signer_mempool| {
        signer_mempool.0.values().flat_map(|scope_mempool| &scope_mempool.transactions)
      }))
      .map(Transaction::hash)
      .collect();
    db::Transactions::set(txn, self.genesis, &mempool);
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
      .map(|signer| (signer, SignerMempool::new()))
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
            .add(txn, genesis, signer, scope, nonce, hash, transaction)
            .expect("transaction saved into mempool couldn't be reloaded into signer's mempool");
        }
      }
    }

    let mut result = UnSigned { genesis, rate_limit, unsigned, signed };
    result.save(txn);
    result
  }

  /// Censure a validator.
  pub(super) fn censure(&mut self, txn: &mut impl DbTxn, validator: [u8; 32]) {
    db::Censured::set(txn, self.genesis, validator, &());
    for transaction in self
      .signed
      .remove(&validator)
      .into_iter()
      .flat_map(|signer_mempool| signer_mempool.0)
      .flat_map(|(_scope, scope_mempool)| scope_mempool.transactions)
    {
      db::Transaction::<T>::del(txn, self.genesis, transaction.hash());
    }
    self.save(txn);
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
    crate::transaction::verify_syntax(&transaction, self.genesis)?;

    let hash = transaction.hash();

    let mut prune = None;
    let transaction: &T = match transaction.kind() {
      TransactionKind::Provided { .. } => panic!("provided transaction being added to the mempool"),
      TransactionKind::Unsigned => {
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
        let signer_mempool = self
          .signed
          .get_mut(&signer)
          .ok_or(MempoolError::Invalid(TransactionError::InvalidSigner))?;

        if !bypass_rate_limit {
          // Check this signer's mempool isn't larger than the rate limit
          let Some(rate) = signer_mempool.rate() else { Err(MempoolError::RateLimit)? };
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

        signer_mempool.add(txn, self.genesis, signer, scope, nonce, hash, transaction)?
      }
    };

    db::Transaction::<T>::set(txn, self.genesis, hash, transaction.into());

    if let Some(signer) = prune {
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
      let (scope, scope_mempool) = match signer_mempool.find_unpublishable_transaction() {
        Some((scope, scope_mempool)) => (scope, scope_mempool),
        None => (
          &scope_of_added_transaction,
          signer_mempool
            .0
            .get_mut(&scope_of_added_transaction)
            .expect("added a transaction but its scope doesn't exist within the signer's mempool"),
        ),
      };
      let pruned = scope_mempool
        .transactions
        .pop_back()
        .expect("pruning from a scope in a signer's mempool which is empty");
      let pruned_hash = pruned.hash();
      db::Transaction::<T>::del(txn, self.genesis, pruned_hash);

      if scope_mempool.transactions.is_empty() {
        // TODO: `find_unpublishable_transaction` would ideally return an `Entry`, not `(K, V)`
        let scope = scope.clone();
        signer_mempool.0.remove(&scope);
      }

      // If we added this transaction just to immediately prune it, error accordingly
      if hash == pruned_hash {
        Err(MempoolError::RateLimit)?;
      }
    }

    self.save(txn);

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
    for slash in block.slashes() {
      self.censure(txn, *slash.validator());
    }

    for transaction in block.transactions() {
      match transaction.kind() {
        TransactionKind::Provided { .. } => continue,
        TransactionKind::Unsigned => {
          let hash = transaction.hash();
          db::UnsignedOnChain::set(txn, self.genesis, hash, &());

          if self.unsigned.remove(&hash).is_some() {
            db::Transaction::<T>::del(txn, self.genesis, hash);
          }
        }
        TransactionKind::Signed { scope, signed: Signed { signer, nonce, signature: _ } } => {
          db::SignedOnChain::set(txn, self.genesis, signer, &scope, nonce, &transaction.hash());

          if let Some(signer_mempool) = self.signed.get_mut(&signer) &&
            let alloc::collections::btree_map::Entry::Occupied(scope_mempool_entry) =
              signer_mempool.0.entry(scope)
          {
            let mut iter = PopUntil::new(scope_mempool_entry, nonce);
            while let Some((returned_iter, transaction)) = iter.next() {
              iter = returned_iter;
              db::Transaction::<T>::del(txn, self.genesis, transaction.hash());
            }
          }
        }
      }
    }

    self.save(txn);
  }
}

struct BlockProposal<'mempool, T: 'mempool, I: Iterator<Item = &'mempool T>> {
  last_signer: Option<[u8; 32]>,
  signer_size: Option<usize>,
  iter: I,
}
impl<'mempool, T: 'mempool + Transaction, I: Iterator<Item = &'mempool T>> Iterator
  for BlockProposal<'mempool, T, I>
{
  type Item = &'mempool T;
  fn next(&mut self) -> Option<Self::Item> {
    loop {
      let next_transaction = self.iter.next()?;

      match next_transaction.kind() {
        TransactionKind::Provided { .. } | TransactionKind::Unsigned => {}
        TransactionKind::Signed { scope: _, signed: Signed { signer, nonce: _, signature: _ } } => {
          // If this is a new signer, reset the signer's size
          if self.last_signer.as_ref().is_none_or(|last_signer| last_signer != &signer) {
            self.signer_size = Some(0);
          }
          self.last_signer = Some(signer);

          /*
            While the caller is expected to apply the block's size limit, we still apply the
            block's size limit _to individual signers_. This lets the caller choose how to
            prefer transactions between signers, without providing transactions which
            definitely won't be included, as those would pointlessly increase the amount of
            memory required to represent the values this iterator yields.

            There is a slight caveat to the caller's ability to choose which transactions are
            preferred, as a later scope of a signer could be preferred over an earlier scope,
            but that isn't modeled here.
          */
          self.signer_size = self.signer_size.and_then(|signer_size| {
            crate::serialized_len(next_transaction)
              .ok()
              .and_then(|transaction_size| signer_size.checked_add(transaction_size))
          });
          if let Some(block_size_limit) = T::BLOCK_SIZE_LIMIT &&
            self.signer_size.is_none_or(|signer_size| signer_size >= block_size_limit)
          {
            continue;
          }
        }
      }

      break Some(next_transaction);
    }
  }
}

impl<T: Transaction> UnSigned<T> {
  /// Create an iterator over the transactions for a block proposal.
  ///
  /// The transactions will be sorted according to the requirements for a block's syntactic
  /// validity. This will only yield the transactions which are ready to be included on-chain.
  ///
  /// The caller is expected to apply the block's size limit.
  pub(super) fn block_proposal(&self) -> impl Iterator<Item = &T> {
    BlockProposal {
      last_signer: None,
      signer_size: Some(0),
      iter: self.unsigned.values().chain(self.signed.values().flat_map(|signer_mempool| {
        signer_mempool.0.values().flat_map(ScopeMempool::iter_with_prior)
      })),
    }
  }
}
