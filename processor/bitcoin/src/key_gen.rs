use ciphersuite::{group::GroupEncoding, Ciphersuite, Secp256k1};
use frost::ThresholdKeys;

use crate::{primitives::x_coord_to_even_point, scan::scanner};

pub(crate) struct KeyGenParams;
impl key_gen::KeyGenParams for KeyGenParams {
  const ID: &'static str = "Bitcoin";

  type ExternalNetworkCurve = Secp256k1;

  fn tweak_keys(keys: &mut ThresholdKeys<Self::ExternalNetworkCurve>) {
    *keys = bitcoin_serai::wallet::tweak_keys(keys);
    // Also create a scanner to assert these keys, and all expected paths, are usable
    scanner(keys.group_key());
  }

  fn encode_key(key: <Self::ExternalNetworkCurve as Ciphersuite>::G) -> Vec<u8> {
    let key = key.to_bytes();
    let key: &[u8] = key.as_ref();
    // Skip the parity encoding as we know this key is even
    key[1 ..].to_vec()
  }

  fn decode_key(key: &[u8]) -> Option<<Self::ExternalNetworkCurve as Ciphersuite>::G> {
    x_coord_to_even_point(key)
  }
}
