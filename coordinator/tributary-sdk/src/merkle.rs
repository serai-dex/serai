use core::borrow::Borrow;
use alloc::boxed::Box;
use std::io;

use blake2::{
  digest::{CustomizedInit as _, Update, Digest as _},
  Blake2b256,
};

/// The representation of an empty tree.
pub const EMPTY_TREE: [u8; 32] = [0; 32];
/// The personalization string used to hash a leaf.
pub const LEAF_PERSONALIZATION: &[u8] = b"tributary leaf";
/// The personalization string used to for a branch's hash.
pub const BRANCH_PERSONALIZATION: &[u8] = b"tributary branch";

/// An item which can update a digest via [`blake2::digest::Update`].
pub trait Digestible {
  /// Update the digest with this value.
  fn update(&self, digest: &mut (impl ?Sized + Update));
  /// Update the digest with this value, returning the digest.
  fn chain_update<U: Update>(&self, mut digest: U) -> U {
    self.update(&mut digest);
    digest
  }
}

impl<B: ?Sized + AsRef<[u8]>> Digestible for B {
  fn update(&self, digest: &mut (impl ?Sized + Update)) {
    digest.update(self.as_ref());
  }
}

pub(crate) struct DigestWriter<'digest, U: ?Sized + Update>(pub(crate) &'digest mut U);
impl<U: ?Sized + Update> io::Write for DigestWriter<'_, U> {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    self.0.update(buf);
    Ok(buf.len())
  }
  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}

/// Compute a Merkle tree's root.
///
/// This tree uses BLAKE2b-256 for its hash function. At the start, all leaves are hashed with a
/// personalization of "tributary leaf". Branches are hashed with a personalization of
/// "tributary branch".
///
/// If a level of the tree is uneven, the last hash is propagated as-is. This means leaves may be
/// at distinct levels of the tree, but gives each leaf a unique path and does not include any
/// magic leaves (such as the zero hash for padding).
///
/// If the tree is empty, an all-zero hash is returned. If the tree only had a single leaf, the
/// leaf's hash will be the tree root (having calculated no branches).
///
/// This function runs in variable time and MAY panic or have undefined behavior if the iterator's
/// size is incorrect.
/*
  TODO: Confirm this personalization matches vectors from the reference implementation.
  https://github.com/monero-oxide/monero-oxide/pull/176 showed the `blake2` crate sometimes
  differs due to API constraints.
*/
pub fn root<D: ?Sized + Digestible>(
  leaves: impl IntoIterator<Item = impl Borrow<D>, IntoIter: ExactSizeIterator>,
) -> [u8; 32] {
  let mut scratch = {
    let leaves = leaves.into_iter();
    let mut scratch = Box::<[[u8; 32]]>::new_uninit_slice(leaves.len());
    let mut len = 0;
    for (scratch, leaf) in scratch.iter_mut().zip(leaves) {
      scratch.write(
        leaf
          .borrow()
          .chain_update(Blake2b256::new_customized(LEAF_PERSONALIZATION))
          .finalize()
          .into(),
      );
      len += 1;
    }
    assert_eq!(scratch.len(), len, "`ExactSizeIterator::len` was incorrect");

    /*
      We just initialized each element according to `ExactSizeIterator::len` and asserted its
      returned length was correct.
    */
    unsafe { scratch.assume_init() }
  };
  let mut scratch = scratch.as_mut();

  while scratch.len() > 1 {
    let pairs = scratch.len() / 2;
    for i in 0 .. pairs {
      scratch[i] = Blake2b256::new_customized(BRANCH_PERSONALIZATION)
        .chain_update(scratch[2 * i])
        .chain_update(scratch[(2 * i) + 1])
        .finalize()
        .into();
    }

    let new_len = if (scratch.len() % 2) == 1 {
      scratch[pairs] = *scratch.last().unwrap();
      pairs + 1
    } else {
      pairs
    };

    scratch = &mut scratch[.. new_len];
  }

  scratch.first().copied().unwrap_or(EMPTY_TREE)
}

#[test]
fn merkle_tree_root() {
  use alloc::{vec::Vec, vec};
  use rand::{RngCore as _, rngs::OsRng};

  fn root2(leaves: &[[u8; 64]]) -> [u8; 32] {
    if leaves.is_empty() {
      return [0; 32];
    }
    let mut leaves = leaves
      .iter()
      .map(|leaf| Blake2b256::new_customized(b"tributary leaf").chain_update(leaf).finalize())
      .collect::<Vec<_>>();

    while leaves.len() != 1 {
      let (chunks, extra) = leaves.as_slice().as_chunks::<2>();
      let mut new_leaves = vec![];
      for [l, r] in chunks {
        new_leaves.push(
          Blake2b256::new_customized(b"tributary branch")
            .chain_update(l)
            .chain_update(r)
            .finalize(),
        );
      }
      assert!(extra.len() <= 1);
      for extra in extra {
        new_leaves.push(*extra);
      }
      leaves = new_leaves;
    }

    leaves[0].into()
  }

  assert_eq!(root::<[u8; 0]>(&[]), root2(&[]));
  for len in 1 .. 32 {
    let mut leaves = vec![[0xff; 64]; len];
    for leaf in &mut leaves {
      OsRng.fill_bytes(leaf);
    }
    assert_eq!(root::<[u8; 64]>(leaves.iter()), root2(&leaves));
  }
}
