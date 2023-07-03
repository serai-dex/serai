use crate::hash;

pub fn merkle_root(root: [u8; 32], leafs: &[[u8; 32]]) -> [u8; 32] {
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

      // Merge hashes until we're at the low_pow_2
      let mut i = high_pow_2 - hashes.len();
      while hashes.len() != low_pow_2 {
        let l = hashes.remove(i);
        let r = hashes.remove(i);
        hashes.insert(i, hash(&[l.as_ref(), &r].concat()));
        i += 1;
      }
      assert_eq!(hashes.len(), i);
      assert_eq!(hashes.len(), low_pow_2);

      // Do a traditional pairing off
      let mut new_hashes = Vec::with_capacity(hashes.len() / 2);
      while hashes.len() > 2 {
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
