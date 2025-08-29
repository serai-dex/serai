#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use zeroize::Zeroize;

use sha2::Sha512;

use ciphersuite::Ciphersuite;

pub use k256;
pub use p256;

macro_rules! kp_curve {
  (
    $feature: literal,
    $lib:     ident,

    $Ciphersuite: ident,
    $ID:          literal
  ) => {
    impl Ciphersuite for $Ciphersuite {
      type F = $lib::Scalar;
      type G = $lib::ProjectivePoint;
      type H = Sha512;

      const ID: &'static [u8] = $ID;

      fn generator() -> Self::G {
        $lib::ProjectivePoint::GENERATOR
      }
    }
  };
}

/// Ciphersuite for Secp256k1.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Secp256k1;
kp_curve!("secp256k1", k256, Secp256k1, b"secp256k1");
#[test]
fn test_secp256k1() {
  ff_group_tests::group::test_prime_group_bits::<_, k256::ProjectivePoint>(&mut rand_core::OsRng);
}

/// Ciphersuite for P-256.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct P256;
kp_curve!("p256", p256, P256, b"P-256");
#[test]
fn test_p256() {
  ff_group_tests::group::test_prime_group_bits::<_, p256::ProjectivePoint>(&mut rand_core::OsRng);
}
