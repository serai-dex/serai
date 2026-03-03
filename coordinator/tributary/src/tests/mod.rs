use ciphersuite::group::GroupEncoding;
use ciphersuite::WrappedGroup;
use dalek_ff_group::{Ristretto, RistrettoPoint};
use rand::{CryptoRng, RngCore};

use serai_primitives::{
  address::SeraiAddress,
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
};

use zeroize::Zeroizing;

pub mod transaction;
pub mod db;
pub mod scan_block;

pub(crate) fn default_test_validator_set() -> ExternalValidatorSet {
  // The external validator set does not alter or affect the behavior of the functions being tested
  // this can be used just as a default value any time
  ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) }
}

pub(crate) fn random_key<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> Zeroizing<<Ristretto as WrappedGroup>::F> {
  Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut *rng))
}

pub(crate) fn get_key_point(key: Zeroizing<<Ristretto as WrappedGroup>::F>) -> RistrettoPoint {
  Ristretto::generator() * *key
}

pub(crate) fn random_serai_address_and_key<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> (RistrettoPoint, SeraiAddress) {
  let key = get_key_point(random_key(rng));
  (key, SeraiAddress(key.to_bytes()))
}
