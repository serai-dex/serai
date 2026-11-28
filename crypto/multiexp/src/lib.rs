#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use zeroize::Zeroize;
use subtle::{ConstantTimeEq as _, ConditionallySelectable};

use ff::PrimeFieldBits;
use group::Group;

#[cfg(feature = "alloc")]
mod straus;
#[cfg(feature = "alloc")]
mod pippenger;

#[cfg(feature = "batch")]
mod batch;

#[cfg(all(test, feature = "alloc"))]
mod tests;

#[cfg(feature = "alloc")]
mod underlying {
  use super::*;

  use core::hint::black_box;
  use alloc::{vec, vec::Vec};

  pub(crate) use straus::*;

  pub(crate) use pippenger::*;

  #[cfg(feature = "batch")]
  pub use batch::BatchVerifier;

  fn u8_from_bool(bit_ref: &mut bool) -> u8 {
    let bit_ref = black_box(bit_ref);

    let mut bit = black_box(*bit_ref);
    #[expect(clippy::cast_lossless, clippy::as_conversions)]
    let res = black_box(bit as u8);
    bit.zeroize();
    debug_assert!(bool::from((res | 1).ct_eq(&1)));

    bit_ref.zeroize();
    res
  }

  // Convert scalars to `window`-sized signed digits, as needed to index a table
  // This algorithm works for `window <= 15`
  pub(crate) fn prep_bits<G: Group<Scalar: PrimeFieldBits>>(
    pairs: &[(G::Scalar, G)],
    window: u8,
  ) -> Vec<Vec<u16>> {
    let w_usize = usize::from(window);
    // The final carry needs one more bit than the scalar has
    let digits =
      (usize::try_from(<G::Scalar as ff::PrimeField>::NUM_BITS).unwrap() + 1).div_ceil(w_usize);
    let half = 1 << (window - 1);

    let mut groupings = vec![];
    for pair in pairs {
      let p = groupings.len();
      let mut bits = pair.0.to_le_bits();
      groupings.push(vec![0; digits]);

      // Bits at or above `NUM_BITS` are zero
      let mut bits = bits.iter_mut();
      for digit in &mut groupings[p] {
        for (i, mut bit) in bits.by_ref().take(w_usize).enumerate() {
          let mut bit = u16::from(u8_from_bool(&mut bit));
          *digit |= bit << i;
          bit.zeroize();
        }
      }

      let mut carry = 0;
      for digit in &mut groupings[p] {
        // If `value > half`, use `value - 2^window` and carry 1 into the next digit
        let mut value = *digit + carry;
        carry = (value + (half - 1)) >> window;
        value = value.wrapping_sub(carry << window);
        let mut negative = value >> 15;
        value = (value ^ negative.wrapping_neg()) + negative;
        *digit = (value << 1) | negative;
        value.zeroize();
        negative.zeroize();
      }
      debug_assert!(bool::from(carry.ct_eq(&0)));
    }

    groupings
  }

  // The magnitude of a digit from `prep_bits`, and `1` if it's negative
  pub(crate) fn split_digit(digit: u16) -> (usize, u16) {
    (usize::from(digit >> 1), digit & 1)
  }

  #[derive(Clone, Copy, PartialEq, Eq, Debug)]
  enum Algorithm {
    Null,
    Single,
    Straus(u8),
    Pippenger(u8),
  }

  // Select the algorithm and window with the fewest group operations in the worst case
  fn algorithm<F: PrimeFieldBits>(len: usize) -> Algorithm {
    if len == 0 {
      Algorithm::Null
    } else if len == 1 {
      Algorithm::Single
    } else {
      let len = u64::try_from(len).unwrap();
      let bits = u64::from(F::NUM_BITS);
      (1 ..= 14)
        .flat_map(|window| {
          let digits = (bits + 1).div_ceil(u64::from(window));
          let half = 1 << (window - 1);
          let doublings = (digits - 1) * u64::from(window);

          // Straus builds `half - 1` table entries per point, then adds one per point per digit
          let straus = (len * (half - 1 + digits)) - 1 + doublings;

          // Per digit, Pippenger fills buckets and their running sum with `len - 1` additions
          // It then adds the running sum to the result once per bucket, `half` times
          // The most significant digit only needs `2^(NUM_BITS - doublings)` buckets
          let top = 1 << (bits - doublings);
          let pippenger = (digits * (len - 1)) + ((digits - 1) * half) + top + doublings;

          [(straus, Algorithm::Straus(window)), (pippenger, Algorithm::Pippenger(window))]
        })
        .min_by_key(|(operations, _)| *operations)
        .unwrap()
        .1
    }
  }

  /// Performs a multiexponentiation.
  pub fn multiexp<
    G: Zeroize + ConditionallySelectable + Group<Scalar: Zeroize + PrimeFieldBits>,
  >(
    pairs: &[(G::Scalar, G)],
  ) -> G {
    match pairs.len() {
      0 => G::identity(),
      1 => pairs[0].1 * pairs[0].0,
      // Constant-time Pippenger reads and writes every bucket for each pair, so Straus is faster
      // Window 4 benchmarked fastest, or tied, for `k256`, `dalek-ff-group`, and `helioselene`
      _ => straus(pairs, 4),
    }
  }

  /// Performs a multiexponentiation in variable time, automatically selecting the optimal algorithm
  /// based on the amount of pairs.
  pub fn multiexp_vartime<G: Group<Scalar: PrimeFieldBits>>(pairs: &[(G::Scalar, G)]) -> G {
    match algorithm::<G::Scalar>(pairs.len()) {
      Algorithm::Null => G::identity(),
      Algorithm::Single => pairs[0].1 * pairs[0].0,
      // These functions panic if called without any pairs
      Algorithm::Straus(window) => straus_vartime(pairs, window),
      Algorithm::Pippenger(window) => pippenger_vartime(pairs, window),
    }
  }
}

#[cfg(not(feature = "alloc"))]
mod underlying {
  use super::*;

  /// Performs a multiexponentiation.
  pub fn multiexp<
    G: Zeroize + ConditionallySelectable + Group<Scalar: Zeroize + PrimeFieldBits>,
  >(
    pairs: &[(G::Scalar, G)],
  ) -> G {
    pairs.iter().map(|(scalar, point)| *point * scalar).sum()
  }

  /// Performs a multiexponentiation in variable time.
  pub fn multiexp_vartime<G: Group<Scalar: PrimeFieldBits>>(pairs: &[(G::Scalar, G)]) -> G {
    pairs.iter().map(|(scalar, point)| *point * scalar).sum()
  }
}

pub use underlying::*;
