use rand_core::OsRng;

use group::{ff::Field, prime::PrimeGroup};

use transcript::RecommendedTranscript;

use crate::cross_group::schnorr::SchnorrPoK;

fn test_schnorr<G: PrimeGroup>() {
  let private = G::Scalar::random(&mut OsRng);

  let transcript = RecommendedTranscript::new(b"Schnorr Test");
  assert!(
    SchnorrPoK::prove(
      &mut OsRng,
      &mut transcript.clone(),
      G::generator(),
      private
    ).verify(&mut transcript.clone(), G::generator(), G::generator() * private)
  );
}

#[test]
fn test_secp256k1() {
  test_schnorr::<k256::ProjectivePoint>();
}

#[test]
fn test_ed25519() {
  test_schnorr::<dalek_ff_group::EdwardsPoint>();
}
