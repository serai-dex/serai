use zeroize::Zeroize;

use ff::PrimeFieldBits;
use group::Group;

use crate::prep_bits;

// Pippenger's algorithm for multiexponentiation, as published in the SIAM Journal on Computing
// DOI: 10.1137/0209022
pub(crate) fn pippenger<G: Group<Scalar: PrimeFieldBits>>(
  pairs: &[(G::Scalar, G)],
  window: u8,
) -> G {
  let mut bits = prep_bits(pairs, window);

  let mut res = G::identity();
  for n in (0 .. bits[0].len()).rev() {
    if n != (bits[0].len() - 1) {
      for _ in 0 .. window {
        res = res.double();
      }
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

  bits.zeroize();
  res
}

pub(crate) fn pippenger_vartime<G: Group<Scalar: PrimeFieldBits>>(
  pairs: &[(G::Scalar, G)],
  window: u8,
) -> G {
  let bits = prep_bits(pairs, window);

  let mut res = G::identity();
  for n in (0 .. bits[0].len()).rev() {
    if n != (bits[0].len() - 1) {
      for _ in 0 .. window {
        res = res.double();
      }
    }

    // Use None to represent identity since is_none is likely faster than is_identity
    let mut buckets = vec![None; 2_usize.pow(window.into())];
    for p in 0 .. bits.len() {
      let nibble = usize::from(bits[p][n]);
      if nibble != 0 {
        if let Some(bucket) = buckets[nibble].as_mut() {
          *bucket += pairs[p].1;
        } else {
          buckets[nibble] = Some(pairs[p].1);
        }
      }
    }

    let mut intermediate_sum = None;
    for b in (1 .. buckets.len()).rev() {
      if let Some(bucket) = buckets[b].as_ref() {
        if let Some(intermediate_sum) = intermediate_sum.as_mut() {
          *intermediate_sum += bucket;
        } else {
          intermediate_sum = Some(*bucket);
        }
      }

      if let Some(intermediate_sum) = intermediate_sum.as_ref() {
        res += intermediate_sum;
      }
    }
  }

  res
}
