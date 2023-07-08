use std_shims::vec::Vec;

use crate::hash;

#[must_use]
pub(crate) fn merkle_root(root: [u8; 32], leafs: &[[u8; 32]]) -> [u8; 32] {
  match leafs.len() {
    0 => root,
    1 => hash(&[root, leafs[0]].concat()),
    _ => {
      let mut hashes = Vec::with_capacity(1 + leafs.len());
      hashes.push(root);
      hashes.extend(leafs);

      // Monero preprocess this so the length is a power of 2
      let mut high_pow_2 = 4; // 4 is the lowest value this can be
      while high_pow_2 < hashes.len() {
        high_pow_2 *= 2;
      }
      let low_pow_2 = high_pow_2 / 2;

      // Merge right-most hashes until we're at the low_pow_2
      {
        let overage = hashes.len() - low_pow_2;
        let mut rightmost = hashes.drain((low_pow_2 - overage) ..);
        // This is true since we took overage from beneath and above low_pow_2, taking twice as
        // many elements as overage
        debug_assert_eq!(rightmost.len() % 2, 0);

        let mut paired_hashes = Vec::with_capacity(overage);
        while let Some(left) = rightmost.next() {
          let right = rightmost.next().unwrap();
          paired_hashes.push(hash(&[left.as_ref(), &right].concat()));
        }
        drop(rightmost);

        hashes.extend(paired_hashes);
        assert_eq!(hashes.len(), low_pow_2);
      }

      // Do a traditional pairing off
      let mut new_hashes = Vec::with_capacity(hashes.len() / 2);
      while hashes.len() > 1 {
        let mut i = 0;
        while i < hashes.len() {
          new_hashes.push(hash(&[hashes[i], hashes[i + 1]].concat()));
          i += 2;
        }

        hashes = new_hashes;
        new_hashes = Vec::with_capacity(hashes.len() / 2);
      }
      hashes[0]
    }
  }
}
