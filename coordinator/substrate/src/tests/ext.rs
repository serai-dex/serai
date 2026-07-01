//! Fuzzer tests for `NewSetInformation::tributary_genesis`.
//!
//! Exercises the genesis hash function with random inputs to verify:
//! - Determinism: same input always produces the same hash
//! - Sensitivity: different inputs produce different hashes
//! - Stability: borsh serialization + Blake2b hashing never panics on random data

use rand_core::OsRng;
use rand::{CryptoRng, RngCore};

use serai_tributary_types::{TributaryValidator, TributaryValidatorSet};
use serai_primitives::{
  test_helpers::{
    random_external_validator_set, random_bytes, random_vec_u8, random_ristretto_public_key_bytes,
  },
};

use crate::TributaryValidatorSetInfo;

/// Generate a random `TributaryValidator` using `OsRng`.
#[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
fn random_tributary_validator<R: RngCore + CryptoRng>(rng: &mut R) -> TributaryValidator {
  // The serai auxiliary key must be a valid Ristretto point, not arbitrary bytes.
  let serai_key_bytes = random_ristretto_public_key_bytes(rng);
  let substrate_key_bytes = random_bytes::<_, 32>(rng);
  // Weight must be in a range where the sum of all validators' weights fits in u16.
  let weight = (rng.next_u32() % 1000) as u16;
  TributaryValidator::new(
    serai_key_bytes,
    substrate_key_bytes,
    random_vec_u8(rng, 0 ..= 64),
    weight,
  )
}

/// Generate a random `TributaryValidatorSet` with a given number of validators.
fn random_tributary_validator_set<R: RngCore + CryptoRng>(
  rng: &mut R,
  num_validators: usize,
) -> TributaryValidatorSet {
  let validators: Vec<_> = (0 .. num_validators).map(|_| random_tributary_validator(rng)).collect();
  TributaryValidatorSet::new(validators)
}

/// Generate a random `NewSetInformation` using `OsRng`.
#[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
fn random_new_set_information<R: RngCore + CryptoRng>(rng: &mut R) -> TributaryValidatorSetInfo {
  let num_validators = (rng.next_u32() % 20) as usize;
  TributaryValidatorSetInfo {
    set: random_external_validator_set(rng),
    serai_block: random_bytes::<_, 32>(rng),
    declaration_time: rng.next_u64(),
    tributary_validator_set: random_tributary_validator_set(rng, num_validators),
  }
}

#[test]
fn tributary_genesis() {
  // Determinism
  {
    let info = random_new_set_information(&mut OsRng);
    let hash1 = info.tributary_genesis();
    let hash2 = info.tributary_genesis();
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 32);
  }

  // Changing values produces different hashes
  {
    let sensitivity_iterations = 1_000;
    for _ in 0 .. sensitivity_iterations {
      let info = random_new_set_information(&mut OsRng);
      let original_hash = info.tributary_genesis();

      {
        let mut mutated = info.clone();
        mutated.set.network = match mutated.set.network {
          serai_primitives::network_id::ExternalNetworkId::Bitcoin => {
            serai_primitives::network_id::ExternalNetworkId::Monero
          }
          serai_primitives::network_id::ExternalNetworkId::Ethereum |
          serai_primitives::network_id::ExternalNetworkId::Monero => {
            serai_primitives::network_id::ExternalNetworkId::Bitcoin
          }
        };
        assert_ne!(
          mutated.tributary_genesis(),
          original_hash,
          "hash should differ when network changes"
        );
      }

      {
        let mut mutated = info.clone();
        mutated.set.session.0 = mutated.set.session.0.wrapping_add(1);
        assert_ne!(
          mutated.tributary_genesis(),
          original_hash,
          "hash should differ when session changes"
        );
      }

      {
        let mut mutated = info.clone();
        mutated.serai_block[0] ^= 0xFF;
        assert_ne!(
          mutated.tributary_genesis(),
          original_hash,
          "hash should differ when serai_block changes"
        );
      }

      {
        let mut mutated = info.clone();
        mutated.declaration_time = mutated.declaration_time.wrapping_add(1);
        assert_ne!(
          mutated.tributary_genesis(),
          original_hash,
          "hash should differ when declaration_time changes"
        );
      }

      {
        let mut mutated = info.clone();
        mutated
          .tributary_validator_set
          .initial_tributary_validators
          .push(random_tributary_validator(&mut OsRng));
        assert_ne!(
          mutated.tributary_genesis(),
          original_hash,
          "hash should differ when a validator is added"
        );
      }

      if !info.tributary_validator_set.initial_tributary_validators.is_empty() {
        let mut mutated = info.clone();
        mutated.tributary_validator_set.initial_tributary_validators[0].weight =
          mutated.tributary_validator_set.initial_tributary_validators[0].weight.wrapping_add(1);
        assert_ne!(
          mutated.tributary_genesis(),
          original_hash,
          "hash should differ when validator weight changes"
        );
      }
    }
  }
}
