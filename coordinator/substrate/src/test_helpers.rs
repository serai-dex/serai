use rand::{CryptoRng, RngCore};
use serai_tributary_types::TributaryValidatorSet;
use serai_primitives::{
  test_helpers::{random_bytes, random_external_validator_set},
};

use crate::TributaryValidatorSetInfo;

/// A random [`NewSetInformation`] for tests.
pub fn random_tributary_validator_set_info<R: RngCore + CryptoRng>(
  rng: &mut R,
  tributary_validator_set: TributaryValidatorSet,
) -> TributaryValidatorSetInfo {
  TributaryValidatorSetInfo {
    set: random_external_validator_set(rng),
    serai_block: random_bytes::<_, 32>(rng),
    declaration_time: rng.next_u64(),
    tributary_validator_set,
  }
}
