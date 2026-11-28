use alloc::{vec, vec::Vec};

use ff::PrimeFieldBits;
use group::Group;

use crate::{prep_bits, split_digit};

// Pippenger's algorithm for multiexponentiation, as published in the SIAM Journal on Computing
// DOI: 10.1137/0209022
pub(crate) fn pippenger_vartime<G: Group<Scalar: PrimeFieldBits>>(
  pairs: &[(G::Scalar, G)],
  window: u8,
) -> G {
  let bits = prep_bits(pairs, window);
  let negated = pairs.iter().map(|pair| -pair.1).collect::<Vec<_>>();

  let mut res = G::identity();
  for n in (0 .. bits[0].len()).rev() {
    if n != (bits[0].len() - 1) {
      for _ in 0 .. window {
        res = res.double();
      }
    }

    // Use None to represent identity since is_none is likely faster than is_identity
    let mut buckets = vec![None; 2_usize.pow((window - 1).into()) + 1];
    for p in 0 .. bits.len() {
      let (magnitude, negative) = split_digit(bits[p][n]);
      if magnitude != 0 {
        let point = if negative == 1 { negated[p] } else { pairs[p].1 };
        if let Some(bucket) = buckets[magnitude].as_mut() {
          *bucket += point;
        } else {
          buckets[magnitude] = Some(point);
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
