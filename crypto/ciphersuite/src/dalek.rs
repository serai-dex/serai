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

    #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
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

#[cfg(feature = "ed25519")]
dalek_curve!("ed25519", Ed25519, EdwardsPoint, b"edwards25519");
