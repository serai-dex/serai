use core::marker::PhantomData;
use alloc::{vec, vec::Vec};

use borsh::{BorshSerialize, BorshDeserialize};

use frame_support::pallet_prelude::*;

use serai_abi::{
  primitives::merkle::{UnbalancedMerkleTree, IncrementalUnbalancedMerkleTree as Iumt},
  *,
};

struct IncrementalUnbalancedMerkleTree<
  T: frame_support::StorageValue<Vec<u8>, Query = Option<Vec<u8>>>,
  const BRANCH_TAG: u8 = 1,
  const LEAF_TAG: u8 = 0,
>(PhantomData<T>);
impl<
    T: frame_support::StorageValue<Vec<u8>, Query = Option<Vec<u8>>>,
    const BRANCH_TAG: u8,
    const LEAF_TAG: u8,
  > IncrementalUnbalancedMerkleTree<T, BRANCH_TAG, LEAF_TAG>
{
  /// Create a new Merkle tree, expecting there to be none already present.
  ///
  /// Panics if a Merkle tree was already present.
  fn new_expecting_none() {
    T::mutate(|value| {
      assert!(value.is_none());
      *value = Some(borsh::to_vec(&Iumt::new()).unwrap());
    });
  }
  /// Append a leaf to the Merkle tree.
  ///
  /// Panics if no Merkle tree was present.
  fn append<L: BorshSerialize>(leaf: &L) {
    let leaf = sp_core::blake2_256(&borsh::to_vec(&(LEAF_TAG, leaf)).unwrap());

    T::mutate(|value| {
      let mut tree = Iumt::deserialize_reader(&mut value.as_ref().unwrap().as_slice()).unwrap();
      tree.append(BRANCH_TAG, leaf);
      *value = Some(borsh::to_vec(&tree).unwrap());
    })
  }
  /// Get the unbalanced merkle tree.
  ///
  /// Panics if no Merkle tree was present.
  fn get() -> UnbalancedMerkleTree {
    Iumt::deserialize_reader(&mut T::get().unwrap().as_slice()).unwrap().calculate(BRANCH_TAG)
  }
  /// Take the Merkle tree.
  ///
  /// Panics if no Merkle tree was present.
  fn take() -> UnbalancedMerkleTree {
    T::mutate(|value| {
      let tree = Iumt::deserialize_reader(&mut value.as_ref().unwrap().as_slice()).unwrap();
      *value = None;
      tree.calculate(BRANCH_TAG)
    })
  }
}

#[frame_support::pallet]
mod pallet {
  use super::*;

  /// The set of all blocks prior added to the blockchain.
  #[pallet::storage]
  pub type Blocks<T: Config> = StorageMap<_, Identity, T::Hash, (), OptionQuery>;
  /// The Merkle tree of all blocks added to the blockchain.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type BlocksCommitment<T: Config> = StorageValue<_, Vec<u8>, OptionQuery>;
  pub(super) type BlocksCommitmentMerkle<T> = IncrementalUnbalancedMerkleTree<BlocksCommitment<T>>;

  /// The Merkle tree of all transactions within the current block.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type BlockTransactionsCommitment<T: Config> = StorageValue<_, Vec<u8>, OptionQuery>;
  pub(super) type BlockTransactionsCommitmentMerkle<T> =
    IncrementalUnbalancedMerkleTree<BlockTransactionsCommitment<T>>;

  /// The hashes of events caused by the current transaction.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type TransactionEvents<T: Config> = StorageValue<_, Vec<u8>, OptionQuery>;
  pub(super) type TransactionEventsMerkle<T> = IncrementalUnbalancedMerkleTree<
    TransactionEvents<T>,
    TRANSACTION_EVENTS_COMMITMENT_BRANCH_TAG,
    TRANSACTION_EVENTS_COMMITMENT_LEAF_TAG,
  >;
  /// The roots of the Merkle trees of each transaction's events.
  #[pallet::storage]
  #[pallet::unbounded]
  pub(super) type BlockEventsCommitment<T: Config> = StorageValue<_, Vec<u8>, OptionQuery>;
  pub(super) type BlockEventsCommitmentMerkle<T> = IncrementalUnbalancedMerkleTree<
    BlockEventsCommitment<T>,
    EVENTS_COMMITMENT_BRANCH_TAG,
    EVENTS_COMMITMENT_LEAF_TAG,
  >;

  /// A mapping from an account to its next nonce.
  #[pallet::storage]
  pub type NextNonce<T: Config> =
    StorageMap<_, Blake2_128Concat, T::AccountId, T::Nonce, ValueQuery>;

  #[pallet::config]
  pub trait Config:
    frame_system::Config<
    Block: sp_runtime::traits::Block<Header: sp_runtime::traits::Header<Hash: Into<[u8; 32]>>>,
  >
  {
  }

  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> Pallet<T> {
    pub fn start_transaction() {
      TransactionEventsMerkle::<T>::new_expecting_none();
    }
    // TODO: Have this called
    pub fn on_event(event: impl TryInto<serai_abi::Event>) {
      if let Ok(event) = event.try_into() {
        TransactionEventsMerkle::<T>::append(&event);
      }
    }
    pub fn end_transaction(transaction_hash: [u8; 32]) {
      BlockTransactionsCommitmentMerkle::<T>::append(&transaction_hash);

      let transaction_events_root = TransactionEventsMerkle::<T>::take().root;

      // Append the leaf (the transaction's hash and its events' root) to the block's events'
      // commitment
      BlockEventsCommitmentMerkle::<T>::append(&(&transaction_hash, &transaction_events_root));
    }
  }
}
pub(super) use pallet::*;

pub struct StartOfBlock<T: Config>(PhantomData<T>);
impl<T: Config> frame_support::traits::PreInherents for StartOfBlock<T> {
  fn pre_inherents() {
    let parent_hash = frame_system::Pallet::<T>::parent_hash();
    Blocks::<T>::set(parent_hash, Some(()));
    // TODO: Better detection of genesis
    if parent_hash == Default::default() {
      BlocksCommitmentMerkle::<T>::new_expecting_none();
    } else {
      let parent_hash: [u8; 32] = parent_hash.into();
      BlocksCommitmentMerkle::<T>::append(&parent_hash);
    }

    BlockTransactionsCommitmentMerkle::<T>::new_expecting_none();
    BlockEventsCommitmentMerkle::<T>::new_expecting_none();
  }
}

pub struct EndOfBlock<T: Config>(PhantomData<T>);
impl<T: Config> frame_support::traits::PostTransactions for EndOfBlock<T> {
  fn post_transactions() {
    frame_system::Pallet::<T>::deposit_log(sp_runtime::generic::DigestItem::Consensus(
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
