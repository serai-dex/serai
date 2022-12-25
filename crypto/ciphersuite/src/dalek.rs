use zeroize::Zeroize;

use sha2::{Digest, Sha512};

use group::Group;
use dalek_ff_group::Scalar;

use crate::Ciphersuite;

macro_rules! dalek_curve {
  (
    $feature: literal,

    $Ciphersuite: ident,
    $Point:       ident,
    $ID:          literal
  ) => {
    use dalek_ff_group::$Point;

    #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
    pub struct $Ciphersuite;
    impl Ciphersuite for $Ciphersuite {
      type F = Scalar;
      type G = $Point;
      type H = Sha512;

      const ID: &'static [u8] = $ID;

      fn generator() -> Self::G {
        $Point::generator()
      }

      fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
        Scalar::from_hash(Sha512::new_with_prefix(&[dst, data].concat()))
      }
    }
  };
}

#[cfg(any(test, feature = "ristretto"))]
dalek_curve!("ristretto", Ristretto, RistrettoPoint, b"ristretto");
#[cfg(any(test, feature = "ristretto"))]
#[test]
fn test_ristretto() {
  ff_group_tests::group::test_prime_group_bits::<RistrettoPoint>();

  assert_eq!(
    Ristretto::hash_to_F(
      b"FROST-RISTRETTO255-SHA512-v11nonce",
      &hex::decode(
        "\
81800157bb554f299fe0b6bd658e4c4591d74168b5177bf55e8dceed59dc80c7\
5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e"
      )
      .unwrap()
    )
    .to_bytes()
    .as_ref(),
    &hex::decode("40f58e8df202b21c94f826e76e4647efdb0ea3ca7ae7e3689bc0cbe2e2f6660c").unwrap()
  );
}

#[cfg(feature = "ed25519")]
dalek_curve!("ed25519", Ed25519, EdwardsPoint, b"edwards25519");
#[cfg(feature = "ed25519")]
#[test]
fn test_ed25519() {
  ff_group_tests::group::test_prime_group_bits::<EdwardsPoint>();

  // Ideally, a test vector from RFC-8032 (not FROST) would be here
  // Unfortunately, the IETF draft doesn't provide any vectors for the derived challenges
  assert_eq!(
    Ed25519::hash_to_F(
      b"FROST-ED25519-SHA512-v11nonce",
      &hex::decode(
        "\
9d06a6381c7a4493929761a73692776772b274236fb5cfcc7d1b48ac3a9c249f\
929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509"
      )
      .unwrap()
    )
    .to_bytes()
    .as_ref(),
    &hex::decode("70652da3e8d7533a0e4b9e9104f01b48c396b5b553717784ed8d05c6a36b9609").unwrap()
  );
}
