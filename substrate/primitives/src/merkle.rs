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

  /// Calculate the Merkle tree root for a list of hashes, passed in as their SCALE encoding.
  ///
  /// This method does not perform any allocations and is quite optimized. It is intended to be
  /// called from within the Substrate runtime, a resource-constrained environment. It does take in
  /// an owned Vec, despite solely using it as a mutable slice, due to the trashing of its content.
  ///
  /// Please see the documentation of `UnbalancedMerkleTree` and `UnbalancedMerkleTree::new` for
  /// context on structure.
  ///
  /// A SCALE encoding will be length-prefixed with a Compact number per
  /// https://docs.polkadot.com/polkadot-protocol/basics/data-encoding/#data-types.
  #[doc(hidden)]
  pub fn from_scale_encoded_list_of_hashes(tag: u8, encoding: Vec<u8>) -> Self {
    let mut hashes = encoding;

    // Learn the length of the length prefix
    let length_prefix_len = {
      let mut slice = hashes.as_slice();
      <scale::Compact<u32> as scale::Decode>::skip(&mut slice).unwrap();
      hashes.len() - slice.len()
    };

    // We calculate the hashes in-place to avoid redundant allocations
    let mut hashes = hashes.as_mut_slice();

    let mut amount_of_hashes;
    while {
      amount_of_hashes = (hashes.len() - length_prefix_len) / 32;
      amount_of_hashes > 1
    } {
      let complete_pairs = amount_of_hashes / 2;
      for i in 0 .. complete_pairs {
        // We hash the i'th pair of 32-byte elements
        let hash = {
          // The starting position of these elements
          let start = length_prefix_len + ((2 * i) * 32);
          /*
            We write the tag to the byte before this pair starts.

            In the case of the first pair, this corrupts a byte of the length prefix.

            In the case of the nth pair, this corrupts the prior-hashed pair's second element.
            This is safe as it was already hashed and the data there won't be read again. While
            we do write, and later read, the carried hash outputs to this buffer, those will
            always be written to either a pair's first element or a (n * prior-)hashed pair's
            second element (where n > 2), never the immediately preceding pair's second element.
          */
          hashes[start - 1] = tag;
          sp_core::blake2_256(&hashes[(start - 1) .. (start + 64)])
        };
        // We save this hash to the i'th position
        {
          let start = length_prefix_len + (i * 32);
          hashes[start .. (start + 32)].copy_from_slice(hash.as_slice());
        }
      }

      let mut end_of_hashes_on_next_layer = length_prefix_len + (complete_pairs * 32);

      // If there was an odd hash which wasn't hashed on this layer, carry it
      if (amount_of_hashes % 2) == 1 {
        let mut hash = [0xff; 32];
        hash.copy_from_slice(&hashes[(hashes.len() - 32) ..]);

        let start = end_of_hashes_on_next_layer;
        end_of_hashes_on_next_layer = start + 32;
        hashes[start .. end_of_hashes_on_next_layer].copy_from_slice(&hash);
      }

      hashes = &mut hashes[.. end_of_hashes_on_next_layer];
    }

    match hashes[length_prefix_len ..].try_into() {
      Ok(root) => Self { root },
      Err(_) => Self::EMPTY,
    }
  }
}

/// An unbalanced Merkle tree which is incrementally created.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
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
    // The reference method, easy to audit, should have identical behavior to the optimized method
    assert_eq!(
      with_new,
      UnbalancedMerkleTree::from_scale_encoded_list_of_hashes(tag, list_of_hashes.encode())
    );
    // The encoding of a slice should work the same as the encoding of a list
    assert_eq!(
      with_new,
      UnbalancedMerkleTree::from_scale_encoded_list_of_hashes(
        tag,
        list_of_hashes.as_slice().encode()
      )
    );
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
