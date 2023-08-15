use rand_core::OsRng;

use transcript::RecommendedTranscript;
use ciphersuite::{group::Group, Ciphersuite, Ed25519};

pub use crate::ringct::bulletproofs_plus::*;

#[cfg(test)]
mod weighted_inner_product;
#[cfg(test)]
mod aggregate_range_proof;

pub fn generators(n: usize) -> Generators<Ed25519> {
  assert_eq!(padded_pow_of_2(n), n, "amount of generators wasn't a power of 2");

  let gens = crate::ringct::bulletproofs::BULLETPROOFS_PLUS_GENERATORS();
  Generators::new(Ed25519::generator(), *crate::H(), gens.G, gens.H)
}
