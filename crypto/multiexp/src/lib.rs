use group::Group;

mod straus;
use straus::*;

mod pippenger;
use pippenger::*;

#[cfg(feature = "batch")]
mod batch;
#[cfg(feature = "batch")]
pub use batch::BatchVerifier;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Algorithm {
  Straus,
  Pippenger
}

fn algorithm(pairs: usize) -> Algorithm {
  // TODO: Replace this with an actual formula determining which will use less additions
  // Right now, Straus is used until 600, instead of the far more accurate 300, as Pippenger
  // operates per byte instead of per nibble, and therefore requires a much longer series to be
  // performant
  // Technically, 800 is dalek's number for when to use byte Pippenger, yet given Straus's own
  // implementation limitations...
  if pairs < 600 {
    Algorithm::Straus
  } else {
    Algorithm::Pippenger
  }
}

// Performs a multiexp, automatically selecting the optimal algorithm based on amount of pairs
// Takes in an iterator of scalars and points, with a boolean for if the scalars are little endian
// encoded in their Reprs or not
pub fn multiexp<G: Group>(pairs: &[(G::Scalar, G)], little: bool) -> G {
  match algorithm(pairs.len()) {
    Algorithm::Straus => straus(pairs, little),
    Algorithm::Pippenger => pippenger(pairs, little)
  }
}

pub fn multiexp_vartime<G: Group>(pairs: &[(G::Scalar, G)], little: bool) -> G {
  match algorithm(pairs.len()) {
    Algorithm::Straus => straus_vartime(pairs, little),
    Algorithm::Pippenger => pippenger_vartime(pairs, little)
  }
}
