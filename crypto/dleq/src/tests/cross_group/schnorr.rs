use rand_core::OsRng;

use zeroize::Zeroize;

use group::{
  ff::{Field, PrimeFieldBits},
  prime::PrimeGroup,
};
use multiexp::BatchVerifier;

use transcript::{Transcript, RecommendedTranscript};

use crate::cross_group::schnorr::SchnorrPoK;

fn test_schnorr<G: PrimeGroup>()
where
  G::Scalar: PrimeFieldBits + Zeroize,
{
  let private = G::Scalar::random(&mut OsRng);

  let transcript = RecommendedTranscript::new(b"Schnorr Test");
  let mut batch = BatchVerifier::new(3);
  SchnorrPoK::prove(&mut OsRng, &mut transcript.clone(), G::generator(), private).verify(
    &mut OsRng,
    &mut transcript.clone(),
    G::generator(),
    G::generator() * private,
    &mut batch,
  );
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
