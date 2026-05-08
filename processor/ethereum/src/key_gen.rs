use ciphersuite::*;
use dkg::{ThresholdKeys, Curves};

use ethereum_schnorr::PublicKey;

/// Secp256k1, and an elliptic curve defined over its scalar field (secq256k1).
pub struct Secp256k1;
impl Curves for Secp256k1 {
  type ToweringCurve = ciphersuite_kp256::Secp256k1;
  type EmbeddedCurve = secq256k1::Secq256k1;
  type EmbeddedCurveParameters = secq256k1::Secq256k1;
}

pub(crate) struct KeyGenParams;
impl key_gen::KeyGenParams for KeyGenParams {
  const ID: &'static str = "Ethereum";

  type ExternalNetworkCiphersuite = Secp256k1;

  fn tweak_keys(
    keys: &mut ThresholdKeys<<Self::ExternalNetworkCiphersuite as Curves>::ToweringCurve>,
  ) {
    while PublicKey::new(keys.group_key()).is_none() {
      *keys = keys.clone().offset(<<Secp256k1 as Curves>::ToweringCurve as WrappedGroup>::F::ONE);
    }
  }

  fn encode_key(
    key: <<Self::ExternalNetworkCiphersuite as Curves>::ToweringCurve as WrappedGroup>::G,
  ) -> Vec<u8> {
    PublicKey::new(key).unwrap().eth_repr().to_vec()
  }

  fn decode_key(
    key: &[u8],
  ) -> Option<<<Self::ExternalNetworkCiphersuite as Curves>::ToweringCurve as WrappedGroup>::G> {
    PublicKey::from_eth_repr(key.try_into().ok()?).map(|key| key.point())
  }
}
