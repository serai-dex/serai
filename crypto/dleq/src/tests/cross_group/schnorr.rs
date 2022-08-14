use rand_core::OsRng;

use zeroize::Zeroize;

use curve::{
  ff::{Field, PrimeFieldBits},
  group::prime::PrimeGroup,
};
use multiexp::BatchVerifier;

use transcript::{Transcript, RecommendedTranscript};

use crate::cross_group::schnorr::SchnorrPoK;

fn test_schnorr<G: PrimeGroup + Zeroize>()
where
  G::Scalar: PrimeFieldBits + Zeroize,
{
  let transcript = RecommendedTranscript::new(b"Schnorr Test");

  let mut batch = BatchVerifier::new(10);
  for _ in 0 .. 10 {
    let private = G::Scalar::random(&mut OsRng);
    SchnorrPoK::<G>::prove(&mut OsRng, &mut transcript.clone(), G::generator(), private).verify(
      &mut OsRng,
      &mut transcript.clone(),
      G::generator(),
      G::generator() * private,
      &mut batch,
    );
  }

  assert!(batch.verify_vartime());
}

#[test]
fn test_secp256k1() {
  test_schnorr::<k256::ProjectivePoint>();
}

#[test]
fn test_ed25519() {
  test_schnorr::<dalek_ff_group::EdwardsPoint>();
}
