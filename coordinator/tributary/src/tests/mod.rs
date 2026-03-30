use ciphersuite::group::GroupEncoding;
use ciphersuite::WrappedGroup;
use dalek_ff_group::{Ristretto, RistrettoPoint};
use messages::sign::VariantSignId;

use rand::{CryptoRng, RngCore};
use rand_core::OsRng;

use serai_primitives::{
  address::SeraiAddress,
  test_helpers::{random_bytes_32, default_test_validator_set},
};

use tributary_sdk::P2p;
use zeroize::Zeroizing;

pub mod transaction;
pub mod db;
pub mod scan_block;
pub mod scan_tributary;
pub mod tributary;

#[derive(Clone)]
struct MockP2p;
impl P2p for MockP2p {
  fn broadcast(&self, _: [u8; 32], _: Vec<u8>) -> impl Send + core::future::Future<Output = ()> {
    async {}
  }
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

pub(crate) fn random_transaction_id() -> VariantSignId {
  VariantSignId::Transaction(random_bytes_32(&mut OsRng))
}
