use ciphersuite::{group::GroupEncoding, Ciphersuite, Ed25519};
use frost::ThresholdKeys;

pub(crate) struct KeyGenParams;
impl key_gen::KeyGenParams for KeyGenParams {
  const ID: &'static str = "Monero";

  type ExternalNetworkCiphersuite = Ed25519;

  fn tweak_keys(keys: &mut ThresholdKeys<Self::ExternalNetworkCiphersuite>) {}
}
