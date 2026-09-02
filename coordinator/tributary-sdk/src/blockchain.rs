use core::{marker::PhantomData, num::NonZero, time::Duration};
use std::{collections::HashMap, time::SystemTime};

use serai_db::{Get, Transaction as DbTxn};

use crate::{
  ReadWrite,
  tendermint::Commit as CommitStruct,
  transaction::{Signed, TransactionKind, Transaction},
  block::{SemanticError, EphemeralError, BlockError, Block as BlockStruct},
  mempool::ProvidedReader,
};

serai_db::schema!(TributaryBlockchain {
  Tip: (genesis: [u8; 32]) -> [u8; 32],
  Block: <B: ReadWrite>(genesis: [u8; 32], hash: [u8; 32]) -> crate::ReadWriteAsBorsh<B>,
  Commit: (genesis: [u8; 32], block: [u8; 32]) -> CommitStruct,
  BlockAfter: (genesis: [u8; 32], parent: [u8; 32]) -> [u8; 32],
  Slashed: (genesis: [u8; 32], validator: [u8; 32]) -> (),
  Unsigned: (genesis: [u8; 32], hash: [u8; 32]) -> (),
  LastSigned: (genesis: [u8; 32], validator: [u8; 32], scope: &[u8]) -> u64,
  OnChainProvided: (genesis: [u8; 32], scope: &'static [u8]) -> u64,
});

pub(crate) struct Reader<T>(PhantomData<T>);

impl<T: Transaction> Reader<T> {
  pub(crate) fn tip(getter: &impl Get, genesis: [u8; 32]) -> Option<[u8; 32]> {
    Tip::get(getter, genesis)
  }

  pub(crate) fn block(
    getter: &impl Get,
    genesis: [u8; 32],
    hash: [u8; 32],
  ) -> Option<BlockStruct<T>> {
    Block::get(getter, genesis, hash).map(|block| block.0)
  }

  pub(crate) fn commit(
    getter: &impl Get,
    genesis: [u8; 32],
    block: [u8; 32],
  ) -> Option<CommitStruct> {
    Commit::get(getter, genesis, block)
  }

  pub(crate) fn block_after(
    getter: &impl Get,
    genesis: [u8; 32],
    parent: [u8; 32],
  ) -> Option<[u8; 32]> {
    BlockAfter::get(getter, genesis, parent)
  }
}

pub(crate) struct Blockchain<T: Transaction> {
  _T: PhantomData<T>,

  genesis: [u8; 32],
  validators: HashMap<[u8; 32], NonZero<u16>>,

  tip: [u8; 32],
}

impl<T: Transaction> Blockchain<T> {
  pub(crate) fn new(
    getter: &impl Get,
    genesis: [u8; 32],
    validators: HashMap<[u8; 32], NonZero<u16>>,
  ) -> Self {
    Self { _T: PhantomData, genesis, validators, tip: Tip::get(getter, genesis).unwrap_or(genesis) }
  }

  pub(crate) fn validators(&self) -> &HashMap<[u8; 32], NonZero<u16>> {
    &self.validators
  }

  #[must_use]
  pub(crate) fn slashed(&self, getter: &impl Get, validator: [u8; 32]) -> bool {
    Slashed::get(getter, self.genesis, validator).is_some()
  }

  pub(crate) fn tip(&self, getter: &impl Get) -> Option<BlockStruct<T>> {
    Block::<BlockStruct<T>>::get(getter, self.genesis, self.tip).map(|block| block.0)
  }

  pub(crate) fn verify<
    N: ::tendermint::Network<
        [u8; 32],
        [u8; 64],
        crate::tendermint::AggregateSignature,
        crate::ReadWriteAsBorsh<BlockStruct<T>>,
      >,
  >(
    &self,
    getter: &impl Get,
    genesis_time: u64,
    block: &BlockStruct<T>,
  ) -> Result<(), BlockError> {
    if block.parent() != self.tip {
      Err(EphemeralError::UnexpectedParent)?;
    }

    block.verify_syntax(self.genesis)?;

    let deferred_time_error = match (|| -> Result<(), BlockError> {
      let Some(target_block_time) = N::target_block_time()
        .and_then(|target_block_time| u64::try_from(target_block_time.as_millis()).ok())
      else {
        /*
          This is a misconfiguration which we smudge as `EphemeralError::Future`, the time-relevant
          `EphemeralError`. This is so we don't blame the proposer (as we would with a syntactic or
          semantic error), but still error. While we do mis-report the error, this should never
          occur as it's a fundamental misconfiguration.

          Additionally, because the this value is unrepresentable, the actual block addition (if
          attempted) will stall because this value is unrepresentable.

          TODO: Improve this flow
        */
        Err(EphemeralError::Future)?
      };

      // Check this block's time isn't too close to the prior block's
      {
        let prior_block_time = self.tip(getter).map(|block| block.time()).unwrap_or(genesis_time);
        let minimum_time = prior_block_time.checked_add(target_block_time);
        /*
          If we can't represent the minimum time from the prior block, because we can represent
          this block's time, this block's time _must_ be less than the minimum time from the prior
          block.
        */
        if minimum_time.is_none_or(|minimum_time| block.time() < minimum_time) {
          // This block violates the minimum spacing between blocks
          Err(SemanticError::TooSoon)?;
        }
      }

      // Check this block's time isn't in the future
      if Some(block.system_time()?) >
        SystemTime::now().checked_add(
          Duration::from_millis(target_block_time) - N::LATENCY_TIME - N::BLOCK_DOWNLOADING_TIME,
        )
      {
        // This block's time is in the future
        Err(EphemeralError::Future)?;
      }

      Ok(())
    })() {
      Ok(()) => Ok(()),
      // Raise syntactic and semantic errors now
      Err(BlockError::Syntactic(error)) => Err(error)?,
      Err(BlockError::Semantic(error)) => Err(error)?,
      /*
        Defer ephemeral errors for later.

        We will allow blocks which are in the future if they have a commit, we just first wait until
        they're no longer in the future.
      */
      Err(BlockError::Ephemeral(error)) => Err(error),
    };

    for slash in block.slashes() {
      let () = slash
        .verify(self.genesis, &self.validators)
        .map_err(|_| SemanticError::InvalidSlash { validator: *slash.validator() })?;
      if Slashed::get(getter, self.genesis, *slash.validator()).is_some() {
        Err(SemanticError::SlashAlreadyIncluded { validator: *slash.validator() })?;
      }
    }

    /*
      Because the Tributary allows blocks with distinct, or locally missing, provided transactions
      (so long as they've undergone consensus), we explicitly return these errors last.
    */
    let mut deferred_provided_error = Ok(());

    {
      let mut provided_transactions_in_scope = None;
      let mut signed_scope = None;
      for tx in block.transactions() {
        let transaction_hash = tx.hash();
        match tx.kind() {
          TransactionKind::Provided { scope } => {
            if provided_transactions_in_scope
              .as_ref()
              .is_none_or(|(current_scope, _transactions)| &scope != current_scope)
            {
              provided_transactions_in_scope = Some((
                scope,
                ProvidedReader::<T>::locally_provided(
                  getter,
                  self.genesis,
                  scope,
                  OnChainProvided::get(getter, self.genesis, scope.as_bytes()).unwrap_or(0),
                ),
              ));
            }
            deferred_provided_error = deferred_provided_error.and(
              match provided_transactions_in_scope
                .as_mut()
                .and_then(|(_current_scope, transactions)| transactions.next())
              {
                None => Err(BlockError::from(EphemeralError::NotLocallyProvidedTransaction {
                  scope,
                  transaction_hash,
                })),
                Some(expected_hash) => (expected_hash == transaction_hash).ok_or(BlockError::from(
                  SemanticError::DistinctProvided { scope, expected_hash, transaction_hash },
                )),
              },
            );
          }
          TransactionKind::Unsigned => {
            if Unsigned::get(getter, self.genesis, transaction_hash).is_some() {
              Err(SemanticError::UnsignedAlreadyIncluded { transaction_hash })?;
            }
          }
          TransactionKind::Signed { scope, signed: Signed { signer, nonce, signature: _ } } => {
            if signed_scope
              .as_ref()
              .is_none_or(|(current_signer, _current_scope)| current_signer != &signer) &&
              ((!self.validators.contains_key(&signer)) ||
                Slashed::get(getter, self.genesis, signer).is_some() ||
                block
                  .slashes()
                  .binary_search_by_key(&signer, |slash| *slash.validator())
                  .is_ok())
            {
              Err(SemanticError::InvalidSigner { signer })?;
            }

            if signed_scope.as_ref().is_none_or(|(current_signer, current_scope)| {
              (current_signer, current_scope) != (&signer, &scope)
            }) {
              let expected_nonce =
                LastSigned::get(getter, self.genesis, signer, &scope).unwrap_or(0);
              if expected_nonce != nonce {
                Err(SemanticError::Gap {
                  transaction_hash,
                  transaction_nonce: nonce,
                  expected_nonce,
                })?;
              }
              signed_scope = Some((signer, scope));
            }
          }
        }
      }
    }

    /*
      First, return if the block is in the future, as this will still be considered an error _and_
      we will have to wait to perform block addition.
    */
    deferred_time_error?;
    /*
      Now return if there's an error with the provided transactions, which will solely be
      considered an error.
    */
    deferred_provided_error
  }

  /// Add a block to the blockchain.
  ///
  /// `commit` is optional in case the commit for each block was deferred for solely the commit for
  /// the most recent block.
  ///
  /// This MAY panic if the commit is not valid. It is only intended to be called with inputs
  /// already verified to be valid.
  pub(crate) fn add(
    &mut self,
    txn: &mut impl DbTxn,
    block: BlockStruct<T>,
    commit: Option<CommitStruct>,
  ) {
    let hash = block.hash();

    if let Some(commit) = &commit {
      debug_assert!(commit.verify(
        &self.validators,
        &super::tendermint::SignatureScheme::new(self.genesis),
        self.genesis,
        hash
      ));
    }

    self.tip = hash;
    Tip::set(txn, self.genesis, &hash);
    Block::<BlockStruct<T>>::set(txn, self.genesis, hash, (&block).into());
    if let Some(commit) = &commit {
      Commit::set(txn, self.genesis, hash, commit);
    }
    BlockAfter::set(txn, self.genesis, block.parent(), &hash);

    for slash in block.slashes() {
      Slashed::set(txn, self.genesis, slash.validator, &());
    }
    for tx in block.transactions() {
      match tx.kind() {
        TransactionKind::Provided { scope } => {
          let existing = OnChainProvided::get(txn, self.genesis, scope.as_bytes()).unwrap_or(0);
          OnChainProvided::set(txn, self.genesis, scope.as_bytes(), &(existing + 1));
        }
        TransactionKind::Unsigned => Unsigned::set(txn, self.genesis, tx.hash(), &()),
        TransactionKind::Signed { scope, signed: Signed { signer, nonce, signature: _ } } => {
          LastSigned::set(txn, self.genesis, signer, &scope, &nonce);
        }
      }
    }
  }
}
