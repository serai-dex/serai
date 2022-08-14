use sha2::{Digest, Sha512};

use dalek_ff_group::Scalar;

use crate::{curve::Curve, algorithm::Hram};

macro_rules! dalek_curve {
  (
    $Point:      ident,
    $Hram:       ident,

    $ID:      literal,
    $CONTEXT: literal,
    $chal:    literal,
    $digest:  literal,
  ) => {
    use dalek_ff_group::$Point;

    impl Curve for $Point {
      const ID: &'static [u8] = $ID;

      fn hash_msg(msg: &[u8]) -> Vec<u8> {
        Sha512::new()
          .chain_update($CONTEXT)
          .chain_update($digest)
          .chain_update(msg)
          .finalize()
          .to_vec()
      }

      fn hash_binding_factor(binding: &[u8]) -> Self::F {
        Self::hash_to_F(b"rho", binding)
      }

      fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
        Scalar::from_hash(Sha512::new().chain_update($CONTEXT).chain_update(dst).chain_update(msg))
      }
    }

    #[derive(Copy, Clone)]
    pub struct $Hram;
    impl Hram<$Point> for $Hram {
      #[allow(non_snake_case)]
      fn hram(R: &$Point, A: &$Point, m: &[u8]) -> Scalar {
        $Point::hash_to_F($chal, &[&R.compress().to_bytes(), &A.compress().to_bytes(), m].concat())
      }
    }
  };
}

#[cfg(any(test, feature = "ristretto"))]
dalek_curve!(
  RistrettoPoint,
  IetfRistrettoHram,
  b"ristretto",
  b"FROST-RISTRETTO255-SHA512-v5",
  b"chal",
  b"digest",
);

#[cfg(feature = "ed25519")]
dalek_curve!(EdwardsPoint, IetfEd25519Hram, b"edwards25519", b"", b"", b"",);
