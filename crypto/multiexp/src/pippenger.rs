use ff::PrimeFieldBits;
use group::Group;

use crate::prep_bits;

pub(crate) fn pippenger<G: Group>(
  pairs: &[(G::Scalar, G)],
  window: u8
) -> G where G::Scalar: PrimeFieldBits {
  let bits = prep_bits(pairs, window);

  let mut res = G::identity();
  for n in (0 .. bits[0].len()).rev() {
    for _ in 0 .. window {
      res = res.double();
    }

    let mut buckets = vec![G::identity(); 2_usize.pow(window.into())];
    for p in 0 .. bits.len() {
      buckets[usize::from(bits[p][n])] += pairs[p].1;
    }

    let mut intermediate_sum = G::identity();
    for b in (1 .. buckets.len()).rev() {
      intermediate_sum += buckets[b];
      res += intermediate_sum;
    }
  }

  res
}

pub(crate) fn pippenger_vartime<G: Group>(
  pairs: &[(G::Scalar, G)],
  window: u8
) -> G where G::Scalar: PrimeFieldBits {
  let bits = prep_bits(pairs, window);

  let mut res = G::identity();
  for n in (0 .. bits[0].len()).rev() {
    if n != (bits[0].len() - 1) {
      for _ in 0 .. window {
        res = res.double();
      }
    }

    let mut buckets = vec![G::identity(); 2_usize.pow(window.into())];
    for p in 0 .. bits.len() {
      let nibble = usize::from(bits[p][n]);
      if nibble != 0 {
        buckets[nibble] += pairs[p].1;
      }
    }

    let mut intermediate_sum = G::identity();
    for b in (1 .. buckets.len()).rev() {
      intermediate_sum += buckets[b];
      res += intermediate_sum;
    }
  }

  res
}
