use rand_core::OsRng;

use transcript::RecommendedTranscript;
use dalek_ff_group::EdwardsPoint;
use group::Group;

pub use crate::ringct::bulletproofs_plus::*;

#[cfg(test)]
mod weighted_inner_product;
#[cfg(test)]
mod aggregate_range_proof;

pub fn generators(n: usize) -> Generators {
  assert_eq!(padded_pow_of_2(n), n, "amount of generators wasn't a power of 2");

  let gens = crate::ringct::bulletproofs::BULLETPROOFS_PLUS_GENERATORS();
  Generators::new(
    EdwardsPoint::generator(),
    dalek_ff_group::EdwardsPoint(crate::H()),
    gens.G.to_vec(),
    gens.H.to_vec(),
  )
}
