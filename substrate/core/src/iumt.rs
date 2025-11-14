use core::marker::PhantomData;

use borsh::BorshSerialize;

use serai_abi::primitives::merkle::{UnbalancedMerkleTree, IncrementalUnbalancedMerkleTree as Iumt};

/// A wrapper around a `StorageValue` which offers a high-level API as an
/// `IncrementalUnbalancedMerkleTree`.
pub struct IncrementalUnbalancedMerkleTree<
  T: frame_support::StorageValue<Iumt, Query = Option<Iumt>>,
  const BRANCH_TAG: u8,
  const LEAF_TAG: u8,
>(PhantomData<T>);
impl<
    T: frame_support::StorageValue<Iumt, Query = Option<Iumt>>,
    const BRANCH_TAG: u8,
    const LEAF_TAG: u8,
  > IncrementalUnbalancedMerkleTree<T, BRANCH_TAG, LEAF_TAG>
{
  /// Create a new Merkle tree, expecting there to be none already present.
  ///
  /// Panics if a Merkle tree was already present.
  pub fn new_expecting_none() {
    T::mutate(|value| {
      assert!(value.is_none());
      *value = Some(Iumt::new());
    });
  }
  /// Append a leaf to the Merkle tree.
  ///
  /// Panics if no Merkle tree was present.
  pub fn append<L: BorshSerialize>(leaf: &L) {
    let leaf = sp_core::blake2_256(&borsh::to_vec(&(LEAF_TAG, leaf)).unwrap());

    T::mutate(|value| {
      let tree = value.as_mut().unwrap();
      tree.append(BRANCH_TAG, leaf);
    })
  }
  /// Get the unbalanced merkle tree.
  ///
  /// Panics if no Merkle tree was present.
  pub fn get() -> UnbalancedMerkleTree {
    T::get().unwrap().calculate(BRANCH_TAG)
  }
  /// Take the Merkle tree.
  ///
  /// Panics if no Merkle tree was present.
  pub fn take() -> UnbalancedMerkleTree {
    T::mutate(|value| value.take().unwrap().calculate(BRANCH_TAG))
  }
}
