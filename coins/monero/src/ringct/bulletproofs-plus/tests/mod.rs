use rand_core::OsRng;

use transcript::RecommendedTranscript;
use ciphersuite::{group::Group, Ciphersuite, Ed25519};

pub use super::*;

#[cfg(test)]
mod weighted_inner_product;
#[cfg(test)]
mod aggregate_range_proof;

#[cfg(test)]
mod gadgets;

pub fn generators(n: usize) -> Generators<Ed25519> {
  assert_eq!(padded_pow_of_2(n), n, "amount of generators wasn't a power of 2");

  let gens = crate::ringct::bulletproofs::plus::GENERATORS();

  let gens = || {
    let mut res = Vec::with_capacity(n);
    for _ in 0 .. n {
      res.push(C::G::random(&mut OsRng));
    }
    res
  };
  let mut res = Generators::new(
    C::G::random(&mut OsRng),
    C::G::random(&mut OsRng),
    gens.G,
    gens.H,
  );
}
