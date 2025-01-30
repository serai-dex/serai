use ciphersuite::Ed25519;

pub(crate) struct KeyGenParams;
impl key_gen::KeyGenParams for KeyGenParams {
  const ID: &'static str = "Monero";

  type ExternalNetworkCiphersuite = Ed25519;
}
