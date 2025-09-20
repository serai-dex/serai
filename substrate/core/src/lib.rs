#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::marker::PhantomData;

extern crate alloc;

mod iumt;
pub use iumt::*;

#[expect(clippy::cast_possible_truncation)]
#[frame_support::pallet]
pub mod pallet {
  use alloc::vec::Vec;

  use frame_support::pallet_prelude::*;

  use serai_abi::primitives::{prelude::*, merkle::IncrementalUnbalancedMerkleTree as Iumt};

  use super::*;

  /// The set of all blocks prior added to the blockchain.
  #[pallet::storage]
  pub(super) type Blocks<T: Config> = StorageMap<_, Identity, T::Hash, (), OptionQuery>;
  /// The Merkle tree of all blocks added to the blockchain.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type BlocksCommitment<T: Config> = StorageValue<_, Iumt, OptionQuery>;
  pub(super) type BlocksCommitmentMerkle<T> = IncrementalUnbalancedMerkleTree<BlocksCommitment<T>>;

  /// The Merkle tree of all transactions within the current block.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type BlockTransactionsCommitment<T: Config> = StorageValue<_, Iumt, OptionQuery>;
  pub(super) type BlockTransactionsCommitmentMerkle<T> =
    IncrementalUnbalancedMerkleTree<BlockTransactionsCommitment<T>>;

  /// The hashes of events caused by the current transaction.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type TransactionEvents<T: Config> = StorageValue<_, Iumt, OptionQuery>;
  pub(super) type TransactionEventsMerkle<T> = IncrementalUnbalancedMerkleTree<
    TransactionEvents<T>,
    { serai_abi::TRANSACTION_EVENTS_COMMITMENT_BRANCH_TAG },
    { serai_abi::TRANSACTION_EVENTS_COMMITMENT_LEAF_TAG },
  >;
  /// The roots of the Merkle trees of each transaction's events.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type BlockEventsCommitment<T: Config> = StorageValue<_, Iumt, OptionQuery>;
  pub(super) type BlockEventsCommitmentMerkle<T> = IncrementalUnbalancedMerkleTree<
    BlockEventsCommitment<T>,
    { serai_abi::EVENTS_COMMITMENT_BRANCH_TAG },
    { serai_abi::EVENTS_COMMITMENT_LEAF_TAG },
  >;

  /// A mapping from an account to its next nonce.
  #[pallet::storage]
  type NextNonce<T: Config> = StorageMap<_, Blake2_128Concat, SeraiAddress, T::Nonce, ValueQuery>;

  /// Mapping from Serai's events to Substrate's.
  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    /// An event from Serai.
    Event(Vec<u8>),
  }

  #[pallet::config]
  pub trait Config: frame_system::Config<Hash: Into<[u8; 32]>> {}

  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> Pallet<T> {
    /// If a block exists on the current blockchain.
    #[must_use]
    pub fn block_exists(hash: impl scale::EncodeLike<T::Hash>) -> bool {
      Blocks::<T>::contains_key(hash)
    }

    /// The next nonce for an account.
    #[must_use]
    pub fn next_nonce(account: &SeraiAddress) -> T::Nonce {
      NextNonce::<T>::get(account)
    }

    /// Consume the next nonce for an account.
    ///
    /// Panics if the current nonce is `<_>::MAX`.
    pub fn consume_next_nonce(signer: &SeraiAddress) {
      NextNonce::<T>::mutate(signer, |value| {
        *value = value
          .checked_add(&T::Nonce::one())
          .expect("`consume_next_nonce` called when current nonce is <_>::MAX")
      });
    }

    /// The code to run when beginning execution of a transaction.
    ///
    /// The caller MUST ensure two transactions aren't simultaneously started.
    pub fn start_transaction() {
      TransactionEventsMerkle::<T>::new_expecting_none();
    }

    /// Emit an event.
    pub fn emit_event(event: impl Into<serai_abi::Event>) {
      let event = event.into();
      TransactionEventsMerkle::<T>::append(&event);
      Self::deposit_event(Event::Event(borsh::to_vec(&event).unwrap()));
    }

    /// End execution of a transaction.
    pub fn end_transaction(transaction_hash: [u8; 32]) {
      BlockTransactionsCommitmentMerkle::<T>::append(&transaction_hash);

      let transaction_events_root = TransactionEventsMerkle::<T>::take().root;

      // Append the leaf (the transaction's hash and its events' root) to the block's events'
      // commitment
      BlockEventsCommitmentMerkle::<T>::append(&(&transaction_hash, &transaction_events_root));
    }

    /// Fetch all of Serai's events.
    ///
    /// This MUST only be used for testing purposes.
    pub fn events() -> Vec<serai_abi::Event>
    where
      serai_abi::Event: TryFrom<T::RuntimeEvent>,
    {
      frame_system::Pallet::<T>::events()
        .into_iter()
        .filter_map(|e| serai_abi::Event::try_from(e.event).ok())
        .collect()
    }
  }
}
pub use pallet::*;

/// The code to run at the start of a block for this pallet.
pub struct StartOfBlock<T: Config>(PhantomData<T>);
impl<T: Config> frame_support::traits::PreInherents for StartOfBlock<T> {
  fn pre_inherents() {
    use frame_support::pallet_prelude::Zero;

    if frame_system::Pallet::<T>::block_number().is_zero() {
      BlocksCommitmentMerkle::<T>::new_expecting_none();
    } else {
      let parent_hash = frame_system::Pallet::<T>::parent_hash();
      Blocks::<T>::set(parent_hash, Some(()));
      let parent_hash: [u8; 32] = parent_hash.into();
      BlocksCommitmentMerkle::<T>::append(&parent_hash);
    }

    BlockTransactionsCommitmentMerkle::<T>::new_expecting_none();
    BlockEventsCommitmentMerkle::<T>::new_expecting_none();
  }
}

/// The code to run at the end of a block for this pallet.
pub struct EndOfBlock<T: Config>(PhantomData<T>);
impl<T: Config> frame_support::traits::PostTransactions for EndOfBlock<T> {
  fn post_transactions() {
    use serai_abi::SeraiExecutionDigest;
    frame_system::Pallet::<T>::deposit_log(
      frame_support::sp_runtime::generic::DigestItem::Consensus(
        SeraiExecutionDigest::CONSENSUS_ID,
        borsh::to_vec(&SeraiExecutionDigest {
          builds_upon: BlocksCommitmentMerkle::<T>::get(),
          transactions_commitment: BlockTransactionsCommitmentMerkle::<T>::take(),
          events_commitment: BlockEventsCommitmentMerkle::<T>::take(),
        })
        .unwrap(),
      ),
    );
  }
}
