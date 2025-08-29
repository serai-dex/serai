use zeroize::Zeroize;

use sha2::Sha512;

use group::Group;
use crate::Scalar;

use ciphersuite::Ciphersuite;

macro_rules! dalek_curve {
  (
    $feature: literal,

    $Ciphersuite: ident,
    $Point:       ident,
    $ID:          literal
  ) => {
    use crate::$Point;

    impl Ciphersuite for $Ciphersuite {
      type F = Scalar;
      type G = $Point;
      type H = Sha512;

      const ID: &'static [u8] = $ID;

      fn generator() -> Self::G {
        $Point::generator()
      }
    }
  };
}

/// Ciphersuite for Ristretto.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Ristretto;
dalek_curve!("ristretto", Ristretto, RistrettoPoint, b"ristretto");
#[test]
fn test_ristretto() {
  ff_group_tests::group::test_prime_group_bits::<_, RistrettoPoint>(&mut rand_core::OsRng);
}

/// Ciphersuite for Ed25519, inspired by RFC-8032.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Ed25519;
dalek_curve!("ed25519", Ed25519, EdwardsPoint, b"edwards25519");
#[test]
fn test_ed25519() {
  ff_group_tests::group::test_prime_group_bits::<_, EdwardsPoint>(&mut rand_core::OsRng);
}
