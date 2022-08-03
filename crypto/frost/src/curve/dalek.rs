use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use sha2::{Digest, Sha512};

use dalek_ff_group::Scalar;

use crate::{curve::Curve, algorithm::Hram};

macro_rules! dalek_curve {
  (
    $Curve:      ident,
    $Hram:       ident,
    $Point:      ident,

    $POINT: ident,

    $ID:      literal,
    $CONTEXT: literal,
    $chal:    literal,
    $digest:  literal,
  ) => {
    use dalek_ff_group::{$Point, $POINT};

    #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
    pub struct $Curve;
    impl Curve for $Curve {
      type F = Scalar;
      type G = $Point;

      const ID: &'static [u8] = $ID;
      const GENERATOR: Self::G = $POINT;

      fn random_nonce<R: RngCore + CryptoRng>(secret: Self::F, rng: &mut R) -> Self::F {
        let mut seed = vec![0; 32];
        rng.fill_bytes(&mut seed);
        seed.extend(&secret.to_bytes());
        Self::hash_to_F(b"nonce", &seed)
      }

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
    impl Hram<$Curve> for $Hram {
      #[allow(non_snake_case)]
      fn hram(R: &$Point, A: &$Point, m: &[u8]) -> Scalar {
        $Curve::hash_to_F($chal, &[&R.compress().to_bytes(), &A.compress().to_bytes(), m].concat())
      }
    }
  };
}

#[cfg(any(test, feature = "ristretto"))]
dalek_curve!(
  Ristretto,
  IetfRistrettoHram,
  RistrettoPoint,
  RISTRETTO_BASEPOINT_POINT,
  b"ristretto",
  b"FROST-RISTRETTO255-SHA512-v5",
  b"chal",
  b"digest",
);

#[cfg(feature = "ed25519")]
dalek_curve!(
  Ed25519,
  IetfEd25519Hram,
  EdwardsPoint,
  ED25519_BASEPOINT_POINT,
  b"edwards25519",
  b"",
  b"",
  b"",
);
