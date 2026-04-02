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
    });
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

#[cfg(test)]
mod tests {
  // Unfortunately, the attribute doesn't accept constants nor macro invocations :/
  // We'd have to define our error messages twice which isn't worth the hassle when we can
  // properly scope our tests to ensure the expected panic was the one hit.
  #![expect(clippy::should_panic_without_expect)]

  use rand_core::{RngCore as _, OsRng};

  use super::*;

  struct Prefix;
  impl frame_support::traits::StorageInstance for Prefix {
    const STORAGE_PREFIX: &'static str = "Storage";
    fn pallet_prefix() -> &'static str {
      "core"
    }
  }
  type Storage = frame_support::storage::types::StorageValue<Prefix, Iumt>;

  #[test]
  fn new_expecting_none() {
    sp_io::TestExternalities::default().execute_with(|| {
      let () = IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::new_expecting_none();
      assert!(Storage::exists());
      std::panic::catch_unwind(
        IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::new_expecting_none,
      )
      .unwrap_err();
    });
  }

  #[test]
  fn append_get_take() {
    sp_io::TestExternalities::default().execute_with(|| {
      let () = IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::new_expecting_none();
      assert_eq!(
        IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::get(),
        UnbalancedMerkleTree::EMPTY
      );

      let mut leaves = vec![];
      for _ in 0 .. 512 {
        let mut leaf = [0; 32];
        OsRng.fill_bytes(&mut leaf);

        let () = IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::append(&leaf);
        leaves.push(sp_core::blake2_256(&borsh::to_vec(&(0u8, leaf)).unwrap()));

        assert_eq!(
          IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::get(),
          UnbalancedMerkleTree::new(1, leaves.clone())
        );
      }

      assert_eq!(
        IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::take(),
        UnbalancedMerkleTree::new(1, leaves.clone())
      );
      assert!(!Storage::exists());
      let () = IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::new_expecting_none();
      assert_eq!(
        IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::take(),
        UnbalancedMerkleTree::EMPTY
      );
    });
  }

  #[test]
  #[should_panic]
  fn append_panics_on_none() {
    sp_io::TestExternalities::default().execute_with(|| {
      IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::append(&());
    });
  }

  #[test]
  #[should_panic]
  fn get_panics_on_none() {
    sp_io::TestExternalities::default().execute_with(|| {
      IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::get();
    });
  }

  #[test]
  #[should_panic]
  fn take_panics_on_none() {
    sp_io::TestExternalities::default().execute_with(|| {
      IncrementalUnbalancedMerkleTree::<Storage, 1, 0>::take();
    });
  }
}
