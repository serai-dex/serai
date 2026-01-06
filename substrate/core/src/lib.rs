#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod limits;
pub use limits::Limits;

mod iumt;
pub use iumt::*;

#[cfg(test)]
mod tests;

#[expect(
  let_underscore_drop,
  clippy::as_conversions,
  clippy::cast_possible_truncation,
  clippy::semicolon_if_nothing_returned
)]
#[frame_support::pallet]
pub mod pallet {
  use alloc::{vec::Vec, vec};

  use frame_support::{
    sp_runtime::{
      traits::{Zero as _, Dispatchable},
      generic::DigestItem,
    },
    weights::Weight,
    dispatch::{DispatchInfo, GetDispatchInfo, PostDispatchInfo},
    traits::{PreInherents, Hooks, BuildGenesisConfig},
    storage::types::{OptionQuery, ValueQuery, StorageValue, StorageMap},
    Identity, Blake2_128Concat,
  };
  use frame_system::pallet_prelude::BlockNumberFor;

  use serai_abi::{
    primitives::{
      BlockHash, address::SeraiAddress, merkle::IncrementalUnbalancedMerkleTree as Iumt,
    },
    TransactionContext,
  };

  use super::*;

  /// The set of all blocks prior added to the blockchain.
  ///
  /// `frame-system` offers the ability to store a window of hashes for recent blocks. While that
  /// could be configured with such a large window it's effectively the entire blockchain, forever,
  /// `frame-system` stores them within an indexed map while we solely need them as a set.
  #[pallet::storage]
  pub(super) type Blocks<T: Config> = StorageMap<_, Identity, T::Hash, (), OptionQuery>;
  /// The Merkle tree of all blocks added to the blockchain.
  ///
  /// This is used to fulfill the `builds_upon` commitment within Serai's header.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type BlocksCommitment<T: Config> = StorageValue<_, Iumt, OptionQuery>;
  pub(super) type BlocksCommitmentMerkle<T> = IncrementalUnbalancedMerkleTree<
    BlocksCommitment<T>,
    { serai_abi::BLOCK_BRANCH_TAG },
    { serai_abi::BLOCK_LEAF_TAG },
  >;

  /// The Merkle tree of all transactions within the current block.
  ///
  /// This is used to fulfill the `transactions_commitment` field within Serai's header.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type BlockTransactionsCommitment<T: Config> = StorageValue<_, Iumt, OptionQuery>;
  pub(super) type BlockTransactionsCommitmentMerkle<T> = IncrementalUnbalancedMerkleTree<
    BlockTransactionsCommitment<T>,
    { serai_abi::TRANSACTION_COMMITMENT_BRANCH_TAG },
    { serai_abi::TRANSACTION_COMMITMENT_LEAF_TAG },
  >;

  /// The hashes of events caused by the current transaction.
  ///
  /// This is used solely as an intermediary location during the lifetime of the transaction
  /// currently being executed.
  #[pallet::storage]
  #[pallet::unbounded]
  type TransactionEvents<T: Config> = StorageValue<_, Iumt, OptionQuery>;
  type TransactionEventsMerkle<T> = IncrementalUnbalancedMerkleTree<
    TransactionEvents<T>,
    { serai_abi::TRANSACTION_EVENTS_COMMITMENT_BRANCH_TAG },
    { serai_abi::TRANSACTION_EVENTS_COMMITMENT_LEAF_TAG },
  >;
  /// The roots of the Merkle trees of each transaction's events.
  ///
  /// This is used to fulfill the `events_commitment` field within Serai's header.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type BlockEventsCommitment<T: Config> = StorageValue<_, Iumt, OptionQuery>;
  pub(super) type BlockEventsCommitmentMerkle<T> = IncrementalUnbalancedMerkleTree<
    BlockEventsCommitment<T>,
    { serai_abi::EVENTS_COMMITMENT_BRANCH_TAG },
    { serai_abi::EVENTS_COMMITMENT_LEAF_TAG },
  >;

  /// A mapping from an account to its next nonce.
  ///
  /// While `frame-system` has such a mapping internally we could defer to, `frame-system` stores
  /// an 'account' which is a larger context than we need here (solely a nonce).
  #[pallet::storage]
  type NextNonce<T: Config> = StorageMap<_, Blake2_128Concat, SeraiAddress, T::Nonce, ValueQuery>;

  /// The current size of the block currently being built/executed.
  #[pallet::storage]
  pub(super) type CurrentBlockSize<T: Config> = StorageValue<_, u32, OptionQuery>;

  /// A wrapper for Serai's events enabling usage of `frame-system`'s event store.
  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    /// A transaction has begun.
    Transaction,
    /// An event from Serai.
    Event(Vec<u8>),
  }

  #[pallet::config]
  pub trait Config:
    Send
    + Sync
    + frame_system::Config<
      Hash = sp_core::H256,
      AccountId = SeraiAddress,
      Nonce = u32,
      BlockLength = Limits,
      BlockWeights = Limits,
      PreInherents = (),
      PostInherents = (),
      PostTransactions = (),
      RuntimeCall: From<serai_abi::Call>
                     + GetDispatchInfo
                     + Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    > + pallet_timestamp::Config<Moment = u64>
  {
    /// The protocol's ID.
    const PROTOCOL_ID: [u8; 32];

    /// The weight for verifying a signed transaction's signature (and context).
    const SIGNATURE_VERIFICATION_WEIGHT: Weight;

    /// Functions to execute before any transactions are executed.
    ///
    /// This is functionally equivalent to [`frame_system::pallet::Config::PreInherents`], but
    /// wrapped within the context of the block's transaction. For more information, please read
    /// the crate's documentation.
    ///
    /// These are NOT invoked for the genesis block.
    type PreInherents: PreInherents;
  }

  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> Pallet<T> {
    /// The code to run on genesis.
    ///
    /// This is usable to build the genesis block's storage and is intended to be as part of a
    /// replacement for [`sp_genesis_builder::GenesisBuilder`](
    ///   https://docs.rs/sp-genesis-builder/0.21.0/sp_genesis_builder/trait.GenesisBuilder.html
    /// ). `GenesisBuilder` is not preferred due to the requirement that the genesis state be
    /// represented as JSON.
    pub fn genesis(config: &impl BuildGenesisConfig) {
      BlocksCommitmentMerkle::<T>::new_expecting_none();
      BlockTransactionsCommitmentMerkle::<T>::new_expecting_none();
      BlockEventsCommitmentMerkle::<T>::new_expecting_none();

      // As each block has a transaction, so does the genesis block
      Self::start_transaction(0);
      <_>::build(config);
      let block_number = sp_core::U256::zero();
      Self::end_transaction(block_number.to_big_endian());

      // `Hooks` are not run for the genesis block by default, so we explicitly run ours here
      Self::on_finalize(frame_system::pallet::Pallet::<T>::block_number());
    }

    /// Emit an event.
    pub fn emit_event(event: impl Into<serai_abi::Event>) {
      let event = event.into();
      TransactionEventsMerkle::<T>::append(&event);
      Self::deposit_event(Event::Event(borsh::to_vec(&event).unwrap()));
    }

    /// Fetch all of Serai's events for each transaction.
    ///
    /// This MUST NOT be called during a transaction/block's execution due to the
    /// computational/memory cost of it.
    pub fn events() -> Vec<Vec<Vec<u8>>>
    where
      T::RuntimeEvent: TryInto<Event<T>>,
    {
      let mut result = vec![];
      for event in frame_system::Pallet::<T>::read_events_no_consensus() {
        match event.event.try_into() {
          Ok(Event::Transaction) => result.push(vec![]),
          Ok(Event::Event(bytes)) => {
            result.last_mut().expect("Serai event outside of a transaction").push(bytes);
          }
          Err(_) => {}
        }
      }
      result
    }
  }

  impl<T: Config> TransactionContext for Pallet<T> {
    const SIGNATURE_VERIFICATION_WEIGHT: Weight = T::SIGNATURE_VERIFICATION_WEIGHT;

    type RuntimeCall = <T as frame_system::Config>::RuntimeCall;

    fn implicit_context() -> serai_abi::ImplicitContext {
      /*
        `frame-system` maintains a rotating window of recent block hashes. While the genesis block
        would be the first block ejected from this rotating window, it's special-cased and always
        preserved by `frame-system` (presumably for its own `CheckGenesis` extension). We rely on
        that here.

        Annoyingly, `BlockHash` implements `ValueQuery` (collapsing if it was set or not), so we
        explicitly use `try_get` here to assert it was in fact set.
      */
      let zero = BlockNumberFor::<T>::zero();
      let genesis_block_hash = frame_system::pallet::BlockHash::<T>::try_get(zero).unwrap().into();

      serai_abi::ImplicitContext { genesis_block_hash, protocol_id: T::PROTOCOL_ID }
    }

    fn current_block_size() -> usize {
      let current_block_size = CurrentBlockSize::<T>::get().unwrap_or(0);
      usize::try_from(current_block_size).unwrap_or(usize::MAX)
    }

    /// If a block is present within the current blockchain.
    fn block_is_present_in_blockchain(hash: &BlockHash) -> bool {
      Blocks::<T>::contains_key(hash)
    }

    fn current_time() -> u64 {
      pallet_timestamp::Pallet::<T>::get()
    }

    /// The next nonce for an account.
    fn next_nonce(signer: &SeraiAddress) -> u32 {
      NextNonce::<T>::get(signer)
    }

    /// The code to run when beginning execution of a transaction.
    ///
    /// The caller MUST ensure two transactions aren't simultaneously started which WILL cause a
    /// panic.
    fn start_transaction(len: usize) {
      {
        let existing_len = CurrentBlockSize::<T>::get().unwrap_or(0);
        let new_len = existing_len.saturating_add(u32::try_from(len).unwrap_or(u32::MAX));
        // We panic here as this should've been caught earlier during validation, and this is fatal
        assert!(new_len <= u32::try_from(serai_abi::Block::MAX_SIZE).unwrap());
        CurrentBlockSize::<T>::set(Some(new_len));
      }

      TransactionEventsMerkle::<T>::new_expecting_none();
      Self::deposit_event(Event::Transaction);
    }

    /// Consume the next nonce for an account.
    ///
    /// Panics if the current nonce is `<_>::MAX`.
    fn consume_next_nonce(signer: &SeraiAddress) {
      NextNonce::<T>::mutate(signer, |value| {
        *value =
          value.checked_add(1).expect("`consume_next_nonce` called when current nonce is <_>::MAX")
      });
    }

    /// End execution of a transaction.
    fn end_transaction(transaction_hash: [u8; 32]) {
      BlockTransactionsCommitmentMerkle::<T>::append(&transaction_hash);

      let transaction_events_root = TransactionEventsMerkle::<T>::take().root;

      // Append the leaf (the transaction's hash and its events' root) to the block's events'
      // commitment
      BlockEventsCommitmentMerkle::<T>::append(&(&transaction_hash, &transaction_events_root));
    }
  }

  #[pallet::hooks] // serai-core-pallet: allow
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(block_number: BlockNumberFor<T>) -> Weight {
      // `Pallet::genesis` is expected to be used for the genesis block
      assert!(!block_number.is_zero());

      // Update the commitment to all prior blocks on the blockchain
      let parent_hash = frame_system::Pallet::<T>::parent_hash();
      Blocks::<T>::set(parent_hash, Some(()));
      let parent_hash: [u8; 32] = parent_hash.into();
      BlocksCommitmentMerkle::<T>::append(&parent_hash);

      BlockTransactionsCommitmentMerkle::<T>::new_expecting_none();
      BlockEventsCommitmentMerkle::<T>::new_expecting_none();

      /*
        We assign the implicit transaction with the block the length of the block itself: its
        header's length and the length of the length-prefix for the list of transactions.

        The length-prefix will be a little-endian `u32`, as `Block` will be borsh-serialized
        (https://borsh.io).

        The length of each actual transaction is expected to be accurate as the SCALE implementation
        defers to the `borsh` serialization.
      */
      assert!(
        CurrentBlockSize::<T>::get().is_none(),
        "AllExtrinsicsLen wasn't killed at the end of the last block"
      );
      Pallet::<T>::start_transaction(serai_abi::Header::SIZE + 4);

      // Handle the `SeraiPreExecutionDigest`
      /*
        These calls panic but this is desired behavior. All blocks, except the genesis, should have
        this and the timestamp should be valid.
      */
      {
        let digest = serai_abi::SeraiPreExecutionDigest::find(&frame_system::Pallet::<T>::digest());
        pallet_timestamp::Pallet::<T>::set(
          frame_system::RawOrigin::None.into(),
          digest.unix_time_in_millis,
        )
        .expect("failed to set timestamp");
      }

      // Execute other modules' `PreInherents`
      <T as Config>::PreInherents::pre_inherents();

      let block_number: sp_core::U256 = frame_system::Pallet::<T>::block_number().into();
      Pallet::<T>::end_transaction(block_number.to_big_endian());

      // We return `Weight::zero` here as this is minute and constant.
      Weight::zero()
    }

    fn on_finalize(_current_number: BlockNumberFor<T>) {
      CurrentBlockSize::<T>::kill();

      use serai_abi::SeraiExecutionDigest;
      frame_system::Pallet::<T>::deposit_log(DigestItem::Consensus(
        SeraiExecutionDigest::CONSENSUS_ID,
        borsh::to_vec(&SeraiExecutionDigest {
          builds_upon: BlocksCommitmentMerkle::<T>::get(),
          transactions_commitment: BlockTransactionsCommitmentMerkle::<T>::take(),
          events_commitment: BlockEventsCommitmentMerkle::<T>::take(),
        })
        .unwrap(),
      ));
    }
  }
}
pub use pallet::*;
