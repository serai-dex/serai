use rand_core::{RngCore, CryptoRng};

use group::Group;

use crate::Curve;

// Test successful multiexp, with enough pairs to trigger its variety of algorithms
// Multiexp has its own tests, yet only against k256 and Ed25519 (which should be sufficient
// as-is to prove multiexp), and this doesn't hurt
pub fn test_multiexp<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let mut pairs = Vec::with_capacity(1000);
  let mut sum = C::G::identity();
  for _ in 0 .. 10 {
    for _ in 0 .. 100 {
      pairs.push((C::random_nonzero_F(&mut *rng), C::generator() * C::random_nonzero_F(&mut *rng)));
      sum += pairs[pairs.len() - 1].1 * pairs[pairs.len() - 1].0;
    }
    assert_eq!(multiexp::multiexp(&pairs), sum);
    assert_eq!(multiexp::multiexp_vartime(&pairs), sum);
  }
}

pub fn test_curve<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  // TODO: Test the Curve functions themselves

  test_multiexp::<_, C>(rng);
}
