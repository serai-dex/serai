use ciphersuite::{group::GroupEncoding, Ciphersuite, Secp256k1};
use frost::ThresholdKeys;

use bitcoin_serai::bitcoin::{hashes::Hash, TapTweakHash};

use crate::{primitives::x_coord_to_even_point, scan::scanner};

pub(crate) struct KeyGenParams;
impl key_gen::KeyGenParams for KeyGenParams {
  const ID: &'static str = "Bitcoin";

  type ExternalNetworkCiphersuite = Secp256k1;

  fn tweak_keys(keys: &mut ThresholdKeys<Self::ExternalNetworkCiphersuite>) {
    /*
      Offset the keys by their hash to prevent a malicious participant from inserting a script
      path, as specified in
      https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-23

      This isn't exactly the same, as we then increment the key until it happens to be even, yet
      the goal is simply that someone who biases the key-gen can't insert their own script path.
      By adding the hash of the key to the key, anyone who attempts such bias will change the key
      used (changing the bias necessary).

      This is also potentially unnecessary for Serai, which uses an eVRF-based DKG. While that can
      be biased (by manipulating who participates as we use it robustly and only require `t`
      participants), contributions cannot be arbitrarily defined. That presumably requires
      performing a search of the possible keys for some collision with 2**128 work. It's better to
      offset regardless and avoid this question however.
    */
    {
      use k256::elliptic_curve::{
        bigint::{Encoding, U256},
        ops::Reduce,
      };
      let tweak_hash = TapTweakHash::hash(&keys.group_key().to_bytes().as_slice()[1 ..]);
      /*
        https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#cite_ref-13-0 states how the
        bias is negligible. This reduction shouldn't ever occur, yet if it did, the script path
        would be unusable due to a check the script path hash is less than the order. That doesn't
        impact us as we don't want the script path to be usable.
      */
      *keys = keys.offset(<Secp256k1 as Ciphersuite>::F::reduce(U256::from_be_bytes(
        *tweak_hash.to_raw_hash().as_ref(),
      )));
    }

    *keys = bitcoin_serai::wallet::tweak_keys(keys);
    // Also create a scanner to assert these keys, and all expected paths, are usable
    scanner(keys.group_key());
  }

  fn encode_key(key: <Self::ExternalNetworkCiphersuite as Ciphersuite>::G) -> Vec<u8> {
    let key = key.to_bytes();
    let key: &[u8] = key.as_ref();
    // Skip the parity encoding as we know this key is even
    key[1 ..].to_vec()
  }

  fn decode_key(key: &[u8]) -> Option<<Self::ExternalNetworkCiphersuite as Ciphersuite>::G> {
    x_coord_to_even_point(key)
  }
}
