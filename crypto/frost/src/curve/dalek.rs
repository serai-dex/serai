use core::convert::TryInto;

use rand_core::{RngCore, CryptoRng};

use sha2::{Digest, Sha512};

use group::{ff::PrimeField, Group};

use dalek_ff_group::Scalar;

use crate::{curve::{CurveError, Curve}, algorithm::Hram};

macro_rules! dalek_curve {
  (
    $Curve:      ident,
    $Hram:       ident,
    $Point:      ident,
    $Compressed: ident,
    $Table:      ident,

    $POINT: ident,
    $TABLE: ident,

    $torsioned: expr,

    $ID:      literal,
    $CONTEXT: literal,
    $chal:    literal,
    $digest:  literal,
  ) => {
    use dalek_ff_group::{$Point, $Compressed, $Table, $POINT, $TABLE};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct $Curve;
    impl Curve for $Curve {
      type F = Scalar;
      type G = $Point;
      type T = &'static $Table;

      const ID: &'static [u8] = $ID;

      const GENERATOR: Self::G = $POINT;
      const GENERATOR_TABLE: Self::T = &$TABLE;

      const LITTLE_ENDIAN: bool = true;

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

      fn F_len() -> usize {
        32
      }

      fn G_len() -> usize {
        32
      }

      fn F_from_slice(slice: &[u8]) -> Result<Self::F, CurveError> {
        let scalar = Self::F::from_repr(
          slice.try_into().map_err(|_| CurveError::InvalidLength(32, slice.len()))?
        );
        if !bool::from(scalar.is_some()) {
          Err(CurveError::InvalidScalar)?;
        }
        Ok(scalar.unwrap())
      }

      fn G_from_slice(slice: &[u8]) -> Result<Self::G, CurveError> {
        let bytes = slice.try_into().map_err(|_| CurveError::InvalidLength(32, slice.len()))?;
        let point = $Compressed::new(bytes).decompress().ok_or(CurveError::InvalidPoint)?;

        // Ban identity
        if point.is_identity().into() {
          Err(CurveError::InvalidPoint)?;
        }
        // Ban torsioned points to meet the prime order group requirement
        if $torsioned(point) {
          Err(CurveError::InvalidPoint)?;
        }
        // Ban points which weren't canonically encoded
        if point.compress().to_bytes() != bytes {
          Err(CurveError::InvalidPoint)?;
        }
        Ok(point)
      }

      fn F_to_bytes(f: &Self::F) -> Vec<u8> {
        f.to_repr().to_vec()
      }

      fn G_to_bytes(g: &Self::G) -> Vec<u8> {
        g.compress().to_bytes().to_vec()
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
  }
}

#[cfg(any(test, feature = "ristretto"))]
dalek_curve!(
  Ristretto,
  IetfRistrettoHram,
  RistrettoPoint,
  CompressedRistretto,
  RistrettoBasepointTable,
  RISTRETTO_BASEPOINT_POINT,
  RISTRETTO_BASEPOINT_TABLE,
  |_| false,
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
  CompressedEdwardsY,
  EdwardsBasepointTable,
  ED25519_BASEPOINT_POINT,
  ED25519_BASEPOINT_TABLE,
  |point: EdwardsPoint| !bool::from(point.is_torsion_free()),
  b"edwards25519",
  b"",
  b"",
  b"",
);
