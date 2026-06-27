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

  // Convert scalars to `window`-sized bit groups, as needed to index a table
  // This algorithm works for `window <= 8`
  pub(crate) fn prep_bits<G: Group<Scalar: PrimeFieldBits>>(
    pairs: &[(G::Scalar, G)],
    window: u8,
  ) -> Vec<Vec<u8>> {
    let w_usize = usize::from(window);

    let mut groupings = vec![];
    for pair in pairs {
      let p = groupings.len();
      let mut bits = pair.0.to_le_bits();
      groupings.push(vec![0; bits.len().div_ceil(w_usize)]);

      for (i, mut bit) in bits.iter_mut().enumerate() {
        let mut bit = u8_from_bool(&mut bit);
        groupings[p][i / w_usize] |= bit << (i % w_usize);
        bit.zeroize();
      }
    }

    groupings
  }

  #[derive(Clone, Copy, PartialEq, Eq, Debug)]
  enum Algorithm {
    Null,
    Single,
    Straus(u8),
    Pippenger(u8),
  }

  // These are 'rule of thumb's obtained via benchmarking `k256` and `curve25519-dalek`
  fn algorithm(len: usize) -> Algorithm {
    #[cfg(not(debug_assertions))]
    if len == 0 {
      Algorithm::Null
    } else if len == 1 {
      Algorithm::Single
    } else if len < 10 {
      // Straus 2 never showed a performance benefit, even with just 2 elements
      Algorithm::Straus(3)
    } else if len < 20 {
      Algorithm::Straus(4)
    } else if len < 50 {
      Algorithm::Straus(5)
    } else if len < 100 {
      Algorithm::Pippenger(4)
    } else if len < 125 {
      Algorithm::Pippenger(5)
    } else if len < 275 {
      Algorithm::Pippenger(6)
    } else if len < 400 {
      Algorithm::Pippenger(7)
    } else {
      Algorithm::Pippenger(8)
    }

    #[cfg(debug_assertions)]
    if len == 0 {
      Algorithm::Null
    } else if len == 1 {
      Algorithm::Single
    } else if len < 10 {
      Algorithm::Straus(3)
    } else if len < 80 {
      Algorithm::Straus(4)
    } else if len < 100 {
      Algorithm::Straus(5)
    } else if len < 125 {
      Algorithm::Pippenger(4)
    } else if len < 275 {
      Algorithm::Pippenger(5)
    } else if len < 475 {
      Algorithm::Pippenger(6)
    } else if len < 750 {
      Algorithm::Pippenger(7)
    } else {
      Algorithm::Pippenger(8)
    }
  }

  /// Performs a multiexponentiation, automatically selecting the optimal algorithm based on the
  /// amount of pairs.
  pub fn multiexp<
    G: Zeroize + ConditionallySelectable + Group<Scalar: Zeroize + PrimeFieldBits>,
  >(
    pairs: &[(G::Scalar, G)],
  ) -> G {
    match algorithm(pairs.len()) {
      Algorithm::Null => Group::identity(),
      Algorithm::Single => pairs[0].1 * pairs[0].0,
      // These functions panic if called without any pairs
      Algorithm::Straus(window) => straus(pairs, window),
      Algorithm::Pippenger(window) => pippenger(pairs, window),
    }
  }

  /// Performs a multiexponentiation in variable time, automatically selecting the optimal algorithm
  /// based on the amount of pairs.
  pub fn multiexp_vartime<G: Group<Scalar: PrimeFieldBits>>(pairs: &[(G::Scalar, G)]) -> G {
    match algorithm(pairs.len()) {
      Algorithm::Null => Group::identity(),
      Algorithm::Single => pairs[0].1 * pairs[0].0,
      Algorithm::Straus(window) => straus_vartime(pairs, window),
      Algorithm::Pippenger(window) => pippenger_vartime(pairs, window),
    }
  }
}

#[cfg(not(feature = "alloc"))]
mod underlying {
  use super::*;

  /// Performs a multiexponentiation, automatically selecting the optimal algorithm based on the
  /// amount of pairs.
  pub fn multiexp<
    G: Zeroize + ConditionallySelectable + Group<Scalar: Zeroize + PrimeFieldBits>,
  >(
    pairs: &[(G::Scalar, G)],
  ) -> G {
    pairs.iter().map(|(scalar, point)| *point * scalar).sum()
  }

  /// Performs a multiexponentiation in variable time, automatically selecting the optimal algorithm
  /// based on the amount of pairs.
  pub fn multiexp_vartime<G: Group<Scalar: PrimeFieldBits>>(pairs: &[(G::Scalar, G)]) -> G {
    pairs.iter().map(|(scalar, point)| *point * scalar).sum()
  }
}

pub use underlying::*;
