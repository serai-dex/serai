use dkg::Participant;
use rand::{CryptoRng, RngCore};

use serai_primitives::test_helpers::{
  random_ristretto_public_key_bytes, random_embedwards_key_bytes, random_bytes,
};
use crate::TributaryValidator;

/// Generate a random 32-byte `networks_external_key`.
pub fn random_external_network_key<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<u8> {
  random_bytes::<R, 32>(rng).to_vec()
}

/// Create a random [`TributaryValidator`] with weight.
pub fn random_tributary_validator<R: RngCore + CryptoRng>(
  rng: &mut R,
  weight: u16,
) -> TributaryValidator {
  TributaryValidator::new(
    random_ristretto_public_key_bytes(rng),
    random_embedwards_key_bytes(rng),
    random_external_network_key(rng),
    weight,
  )
}

/// Get a [`Participant`] from a [`u16`]
pub fn u16_to_participant(n: u16) -> Participant {
  Participant::new(n).unwrap()
}
