use zeroize::Zeroize;

use sha2::{Digest, Sha512};

use group::Group;
use dalek_ff_group::Scalar;

use crate::{curve::Curve, algorithm::Hram};

macro_rules! dalek_curve {
  (
    $feature: literal,

    $Curve:      ident,
    $Hram:       ident,
    $Point:      ident,

    $ID:      literal,
    $CONTEXT: literal,
    $chal: literal,
  ) => {
    use dalek_ff_group::$Point;

    #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
    pub struct $Curve;
    impl Curve for $Curve {
      type F = Scalar;
      type G = $Point;
      type H = Sha512;

      const ID: &'static [u8] = $ID;
      const CONTEXT: &'static [u8] = $CONTEXT;

      fn generator() -> Self::G {
        $Point::generator()
      }

      fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
        Scalar::from_bytes_mod_order_wide(&Self::hash_to_vec(dst, data).try_into().unwrap())
      }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
    #[derive(Copy, Clone)]
    pub struct $Hram;
    impl Hram<$Curve> for $Hram {
      #[allow(non_snake_case)]
      fn hram(R: &$Point, A: &$Point, m: &[u8]) -> Scalar {
        let mut hash = Sha512::new();
        if $chal.len() != 0 {
          hash.update(&[$CONTEXT.as_ref(), $chal].concat());
        }
        Scalar::from_hash(
          hash.chain_update(&[&R.compress().to_bytes(), &A.compress().to_bytes(), m].concat()),
        )
      }
    }
  };
}

#[cfg(any(test, feature = "ristretto"))]
dalek_curve!(
  "ristretto",
  Ristretto,
  IetfRistrettoHram,
  RistrettoPoint,
  b"ristretto",
  b"FROST-RISTRETTO255-SHA512-v11",
  b"chal",
);

#[cfg(feature = "ed25519")]
dalek_curve!(
  "ed25519",
  Ed25519,
  IetfEd25519Hram,
  EdwardsPoint,
  b"edwards25519",
  b"FROST-ED25519-SHA512-v11",
  b"",
);
