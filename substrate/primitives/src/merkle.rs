use alloc::vec::Vec;

use borsh::{BorshSerialize, BorshDeserialize};

/// An unbalanced Merkle tree.
///
/// This Merkle tree represents its leaves once and only once (distinct from a balanced Merkle
/// tree, which would require padding its leaves to a power of two). Accordingly, leaves have
/// canonical paths. This is useful for anyone who wants to index leaves which don't inherently
/// have indexes.
///
/// `[0; 32]` is used to represent an empty tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct UnbalancedMerkleTree {
  /// The root of the tree represented.
  pub root: [u8; 32],
}

impl UnbalancedMerkleTree {
  /// An empty Merkle tree.
  pub const EMPTY: Self = Self { root: [0; 32] };

  /// If this tree is empty of leaves.
  pub fn is_empty(self) -> bool {
    self == Self::EMPTY
  }

  fn branch_hash(tag: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [tag; 65];
    preimage[1 .. 33].copy_from_slice(left);
    preimage[33 ..].copy_from_slice(right);
    sp_core::blake2_256(&preimage)
  }

  /// Create a new Merkle tree from a set of leaves.
  ///
  /// Each branch hash will be prefixed by the specified tag. To ensure branches are not argued
  /// leaves, and vice-versa, the hashes present in the list MUST never have preimages whose first
  /// byte may be the specified tag byte.
  ///
  /// This method performs intermediary allocations necessary to calculate the root.
  pub fn new(tag: u8, leaves: Vec<[u8; 32]>) -> Self {
    if leaves.is_empty() {
      return Self::EMPTY;
    }

    let mut current = leaves;
    let mut next = Vec::with_capacity(current.len().div_ceil(2));
    // Iterate until the root hash
    while current.len() != 1 {
      let mut iter = current.iter();
      while let Some(a) = iter.next() {
        match iter.next() {
          // If we have a pair of hashes, create a branch hash
          Some(b) => {
            next.push(Self::branch_hash(tag, a, b));
          }
          // If we don't, propagate this hash
          None => next.push(*a),
        }
      }
      core::mem::swap(&mut current, &mut next);
      next.clear();
    }
    Self { root: current[0] }
  }
}

/// An unbalanced Merkle tree which is incrementally created.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "non_canonical_scale_derivations", derive(scale::Encode, scale::Decode))]
pub struct IncrementalUnbalancedMerkleTree {
  /// (number of children under branch, branch hash)
  branches: Vec<(u64, [u8; 32])>,
}

impl IncrementalUnbalancedMerkleTree {
  /// Create a new incrementally-created unbalanced merkle tree.
  pub fn new() -> Self {
    Self { branches: Vec::new() }
  }

  /// Reduce the incremental tree.
  ///
  /// We prune the descendants of fully-populated branches.
  fn reduce(&mut self, tag: u8) {
    while {
      // If we have two branches eligible to be merged, and they're of equal depth
      let len = self.branches.len();
      (len >= 2) && (self.branches[len - 2].0 == self.branches[len - 1].0)
    } {
      // Merge them, as the two descendants of this branch, pruning themselves
      let right = self.branches.pop().unwrap();
      let left = self.branches.last_mut().unwrap();
      left.0 *= 2;
      left.1 = UnbalancedMerkleTree::branch_hash(tag, &left.1, &right.1);
    }
  }

  /// Append a leaf to this merkle tree.
  ///
  /// The conditions on this leaf are the same as defined by `UnbalancedMerkleTree::new`.
  ///
  /// This will not calculate any hashes not necessary for the eventual root.
  pub fn append(&mut self, tag: u8, leaf: [u8; 32]) {
    self.branches.push((1, leaf));
    self.reduce(tag);
  }

  /// Calculate the `UnbalancedMerkleTree` for this tree.
  pub fn calculate(mut self, tag: u8) -> UnbalancedMerkleTree {
    if self.branches.is_empty() {
      return UnbalancedMerkleTree::EMPTY;
    }
    while self.branches.len() > 1 {
      // The left-most list elements will have already be hashed at the layer simulated for the
      // right-most list elements. We emulate the hashes upon carries for right-most elements
      {
        let right = self.branches.pop().unwrap();
        let left = self.branches.last_mut().unwrap();
        left.0 *= 2;
        left.1 = UnbalancedMerkleTree::branch_hash(tag, &left.1, &right.1);
      }
      // And then we perform any hashes due to being of equal depth
      self.reduce(tag);
    }
    UnbalancedMerkleTree { root: self.branches[0].1 }
  }
}

#[cfg(feature = "std")]
#[test]
fn unbalanced_merkle_tree() {
  use sp_core::Encode;

  use rand_core::{RngCore, OsRng};

  let tag = u8::try_from(OsRng.next_u64() % u64::from(u8::MAX)).unwrap();
  let mut list_of_hashes = vec![];
  let mut incremental = IncrementalUnbalancedMerkleTree::new();
  for i in 0 ..= 257 {
    assert_eq!(list_of_hashes.len(), i);

    // Calculate the root of the tree
    let with_new = UnbalancedMerkleTree::new(tag, list_of_hashes.clone());
    // Check `is_empty` works
    assert_eq!(with_new.is_empty(), i == 0);
    // Check the incremental method produces an identical result
    assert_eq!(incremental.clone().calculate(tag), with_new, "{i}");

    // If the tree has branches...
    if i > 1 {
      // Changing the tag should change the root hash
      assert!(with_new != UnbalancedMerkleTree::new(tag.wrapping_add(1), list_of_hashes.clone()));
    }

    // Push a new hash onto the list for the next iteration
    {
      let mut hash = [0; 32];
      OsRng.fill_bytes(&mut hash);
      list_of_hashes.push(hash);
      incremental.append(tag, hash);
    }
  }
}
