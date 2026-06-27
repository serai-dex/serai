#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use sha2::Sha512;

use ciphersuite::{WrappedGroup, Id, WithPreferredHash, GroupCanonicalEncoding};

pub use k256;
pub use p256;

macro_rules! kp_curve {
  (
    $feature: literal,
    $lib:     ident,

    $Ciphersuite: ident,
    $ID:          literal
  ) => {
    impl WrappedGroup for $Ciphersuite {
      type F = $lib::Scalar;
      type G = $lib::ProjectivePoint;
      fn generator() -> Self::G {
        $lib::ProjectivePoint::GENERATOR
      }
    }
    impl Id for $Ciphersuite {
      const ID: &[u8] = $ID;
    }
    impl WithPreferredHash for $Ciphersuite {
      type H = Sha512;
    }
    impl GroupCanonicalEncoding for $Ciphersuite {}
  };
}

/// Ciphersuite for Secp256k1.
#[derive(Clone, Copy, Debug)]
pub struct Secp256k1;
kp_curve!("secp256k1", k256, Secp256k1, b"secp256k1");
#[test]
fn test_secp256k1() {
  ff_group_tests::group::test_prime_group_bits::<_, k256::ProjectivePoint>(&mut rand_core::OsRng);
}

/// Ciphersuite for P-256.
#[derive(Clone, Copy, Debug)]
pub struct P256;
kp_curve!("p256", p256, P256, b"P-256");
#[test]
fn test_p256() {
  ff_group_tests::group::test_prime_group_bits::<_, p256::ProjectivePoint>(&mut rand_core::OsRng);
}
