use crate::hash;

/// Round to power of two, for count>=3 and for count being not too large (<= 2^28)
/// (as reasonable for tree hash calculations)
///
fn tree_hash_cnt(count: usize) -> usize {
  // This algo has some bad history but all we are doing is 1 << floor(log2(count))
  // There are _many_ ways to do log2, for some reason the one selected was the most obscure one,
  // and fixing it made it even more obscure.
  //
  // Iterative method implemented below aims for clarity over speed, if performance is needed
  // then my advice is to use the BSR instruction on x86
  //
  // All the paranoid asserts have been removed since it is trivial to mathematically prove that
  // the return will always be a power of 2.
  // Problem space has been defined as 3 <= count <= 2^28. Of course quarter of a billion
  // transactions is not a sane upper limit for a block, so there will be tighter limits
  // in other parts of the code

  assert!(count >= 3); // cases for 0,1,2 are handled elsewhere
  assert!(count <= 0x10000000); // sanity limit to 2^28, MSB=1 will cause an inf loop

  let mut pow = 2_usize;
  while pow < count {
    pow <<= 1
  }

  pow >> 1
}

fn hash_concat(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
  let mut v = [a, b].concat();
  hash(&v)
}

/// Compute tree hash as defined by Cryptonote
pub fn tree_hash(root_hash: [u8; 32], extra_hashes: &[[u8; 32]]) -> [u8; 32] {
  match extra_hashes.len() {
    0 => root_hash,
    1 => hash_concat(root_hash, extra_hashes[0]),
    other => {
      let count = other + 1;

      let mut cnt = tree_hash_cnt(count);

      let mut hashes =
        std::iter::once(root_hash).chain(extra_hashes.iter().copied()).collect::<Vec<_>>();

      let mut i = 2 * cnt - count;
      let mut j = 2 * cnt - count;
      while j < cnt {
        hashes[j] = hash_concat(hashes[i], hashes[i + 1]);
        i += 2;
        j += 1;
      }
      assert_eq!(i, count);

      while cnt > 2 {
        cnt >>= 1;
        for i in 0 .. cnt {
          hashes[i] = hash_concat(hashes[2 * i], hashes[2 * i + 1]);
        }
      }

      hash_concat(hashes[0], hashes[1])
    }
  }
}
