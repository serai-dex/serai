#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
use std_shims::vec::Vec;

use zeroize::Zeroize;

use ff::PrimeFieldBits;
use group::Group;

mod straus;
use straus::*;

mod pippenger;
use pippenger::*;

#[cfg(feature = "batch")]
mod batch;
#[cfg(feature = "batch")]
pub use batch::BatchVerifier;

#[cfg(test)]
mod tests;

// Use black_box when possible
#[rustversion::since(1.66)]
use core::hint::black_box;
#[rustversion::before(1.66)]
fn black_box<T>(val: T) -> T {
  val
}

fn u8_from_bool(bit_ref: &mut bool) -> u8 {
  let bit_ref = black_box(bit_ref);

  let mut bit = black_box(*bit_ref);
  #[allow(clippy::cast_lossless)]
  let res = black_box(bit as u8);
  bit.zeroize();
  debug_assert!((res | 1) == 1);

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
    groupings.push(vec![0; (bits.len() + (w_usize - 1)) / w_usize]);

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

/*
Release (with runs 20, so all of these are off by 20x):

k256
Straus 3 is more efficient at 5 with 678µs per
Straus 4 is more efficient at 10 with 530µs per
Straus 5 is more efficient at 35 with 467µs per

Pippenger 5 is more efficient at 125 with 431µs per
Pippenger 6 is more efficient at 275 with 349µs per
Pippenger 7 is more efficient at 375 with 360µs per

dalek
Straus 3 is more efficient at 5 with 519µs per
Straus 4 is more efficient at 10 with 376µs per
Straus 5 is more efficient at 170 with 330µs per

Pippenger 5 is more efficient at 125 with 305µs per
Pippenger 6 is more efficient at 275 with 250µs per
Pippenger 7 is more efficient at 450 with 205µs per
Pippenger 8 is more efficient at 800 with 213µs per

Debug (with runs 5, so...):

k256
Straus 3 is more efficient at 5 with 2532µs per
Straus 4 is more efficient at 10 with 1930µs per
Straus 5 is more efficient at 80 with 1632µs per

Pippenger 5 is more efficient at 150 with 1441µs per
Pippenger 6 is more efficient at 300 with 1235µs per
Pippenger 7 is more efficient at 475 with 1182µs per
Pippenger 8 is more efficient at 625 with 1170µs per

dalek:
Straus 3 is more efficient at 5 with 971µs per
Straus 4 is more efficient at 10 with 782µs per
Straus 5 is more efficient at 75 with 778µs per
Straus 6 is more efficient at 165 with 867µs per

Pippenger 5 is more efficient at 125 with 677µs per
Pippenger 6 is more efficient at 250 with 655µs per
Pippenger 7 is more efficient at 475 with 500µs per
Pippenger 8 is more efficient at 875 with 499µs per
*/
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
pub fn multiexp<G: Group<Scalar: PrimeFieldBits + Zeroize>>(pairs: &[(G::Scalar, G)]) -> G {
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
