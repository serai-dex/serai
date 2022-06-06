use core::convert::TryInto;

use rand_core::{RngCore, CryptoRng};

use sha2::{Digest, Sha512};

use ff::PrimeField;
use group::Group;

use dalek_ff_group::{
  EdwardsBasepointTable,
  ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE,
  Scalar, EdwardsPoint, CompressedEdwardsY
};

use crate::{CurveError, Curve, algorithm::Hram};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ed25519;
impl Curve for Ed25519 {
  type F = Scalar;
  type G = EdwardsPoint;
  type T = &'static EdwardsBasepointTable;

  const ID: &'static [u8] = b"edwards25519";

  const GENERATOR: Self::G = ED25519_BASEPOINT_POINT;
  const GENERATOR_TABLE: Self::T = &ED25519_BASEPOINT_TABLE;

  const LITTLE_ENDIAN: bool = true;

  fn random_nonce<R: RngCore + CryptoRng>(secret: Self::F, rng: &mut R) -> Self::F {
    let mut seed = vec![0; 32];
    rng.fill_bytes(&mut seed);
    seed.extend(&secret.to_bytes());
    Self::hash_to_F(b"nonce", &seed)
  }

  fn hash_msg(msg: &[u8]) -> Vec<u8> {
    Sha512::digest(msg).to_vec()
  }

  fn hash_binding_factor(binding: &[u8]) -> Self::F {
    Self::hash_to_F(b"rho", binding)
  }

  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
    Scalar::from_hash(Sha512::new().chain_update(dst).chain_update(msg))
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
    if scalar.is_some().unwrap_u8() == 0 {
      Err(CurveError::InvalidScalar)?;
    }
    Ok(scalar.unwrap())
  }

  fn G_from_slice(slice: &[u8]) -> Result<Self::G, CurveError> {
    let bytes = slice.try_into().map_err(|_| CurveError::InvalidLength(32, slice.len()))?;
    let point = CompressedEdwardsY::new(bytes).decompress();

    if let Some(point) = point {
      // Ban identity and torsioned points
      if point.is_identity().into() || (!bool::from(point.is_torsion_free())) {
        Err(CurveError::InvalidPoint)?;
      }
      // Ban points which weren't canonically encoded
      if point.compress().to_bytes() != bytes {
        Err(CurveError::InvalidPoint)?;
      }
      Ok(point)
    } else {
      Err(CurveError::InvalidPoint)
    }
  }

  fn F_to_bytes(f: &Self::F) -> Vec<u8> {
    f.to_repr().to_vec()
  }

  fn G_to_bytes(g: &Self::G) -> Vec<u8> {
    g.compress().to_bytes().to_vec()
  }
}

#[derive(Copy, Clone)]
pub struct IetfEd25519Hram;
impl Hram<Ed25519> for IetfEd25519Hram {
  #[allow(non_snake_case)]
  fn hram(R: &EdwardsPoint, A: &EdwardsPoint, m: &[u8]) -> Scalar {
    Ed25519::hash_to_F(b"", &[&R.compress().to_bytes(), &A.compress().to_bytes(), m].concat())
  }
}
