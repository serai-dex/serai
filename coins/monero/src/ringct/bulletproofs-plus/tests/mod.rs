use rand_core::OsRng;

use transcript::RecommendedTranscript;
use ciphersuite::{group::Group, Ciphersuite, Pallas, Vesta};

use crate::{Generators, padded_pow_of_2};

#[cfg(test)]
mod weighted_inner_product;
#[cfg(test)]
mod single_range_proof;
#[cfg(test)]
mod aggregate_range_proof;

#[cfg(test)]
mod vector_commitment;
#[cfg(test)]
mod gadgets;

pub fn generators<C: Ciphersuite>(n: usize) -> Generators<RecommendedTranscript, C> {
  assert_eq!(padded_pow_of_2(n), n, "amount of generators wasn't a power of 2");

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
    gens(),
    gens(),
    gens(),
    gens(),
  );

  // These use 4 * n since they're for the underlying g_bold, the concat of g_bold1, g_bold2,
  // and are also used to pad out the generators for a specific commitment to the needed length
  let proving_gens = || {
    let mut res = Vec::with_capacity(4 * n);
    for _ in 0 .. (4 * n) {
      res.push(C::G::random(&mut OsRng));
    }
    res
  };
  res.add_vector_commitment_proving_generators(
    (C::G::random(&mut OsRng), C::G::random(&mut OsRng)),
    (proving_gens(), proving_gens()),
  );
  res
}
