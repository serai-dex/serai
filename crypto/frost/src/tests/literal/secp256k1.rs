use core::convert::TryInto;

use rand::rngs::OsRng;

use ff::PrimeField;
use group::GroupEncoding;

use sha2::{Digest, Sha256, Sha512};

use k256::{
  elliptic_curve::{generic_array::GenericArray, bigint::{ArrayEncoding, U512}, ops::Reduce},
  Scalar,
  ProjectivePoint
};

use crate::{CurveError, Curve, algorithm::Hram, tests::curve::test_curve};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Secp256k1;
impl Curve for Secp256k1 {
  type F = Scalar;
  type G = ProjectivePoint;
  type T = ProjectivePoint;

  fn id() -> String {
    "secp256k1".to_string()
  }

  fn id_len() -> u8 {
    Self::id().len() as u8
  }

  fn generator() -> Self::G {
    Self::G::GENERATOR
  }

  fn generator_table() -> Self::T {
    Self::G::GENERATOR
  }

  fn little_endian() -> bool {
    false
  }

  // The IETF draft doesn't specify a secp256k1 ciphersuite
  // This test just uses the simplest ciphersuite which would still be viable to deploy
  fn hash_msg(msg: &[u8]) -> Vec<u8> {
    (&Sha256::digest(msg)).to_vec()
  }

  // Use wide reduction for security
  fn hash_to_F(data: &[u8]) -> Self::F {
    Scalar::from_uint_reduced(
      U512::from_be_byte_array(Sha512::new().chain_update("rho").chain_update(data).finalize())
    )
  }

  fn F_len() -> usize {
    32
  }

  fn G_len() -> usize {
    33
  }

  fn F_from_slice(slice: &[u8]) -> Result<Self::F, CurveError> {
    let bytes: [u8; 32] = slice.try_into()
      .map_err(|_| CurveError::InvalidLength(32, slice.len()))?;
    let scalar = Scalar::from_repr(bytes.into());
    if scalar.is_none().unwrap_u8() == 1 {
      Err(CurveError::InvalidScalar)?;
    }
    Ok(scalar.unwrap())
  }

  fn G_from_slice(slice: &[u8]) -> Result<Self::G, CurveError> {
    let point = ProjectivePoint::from_bytes(GenericArray::from_slice(slice));
    if point.is_none().unwrap_u8() == 1 {
      Err(CurveError::InvalidScalar)?;
    }
    Ok(point.unwrap())
  }

  fn F_to_bytes(f: &Self::F) -> Vec<u8> {
    (&f.to_bytes()).to_vec()
  }

  fn G_to_bytes(g: &Self::G) -> Vec<u8> {
    (&g.to_bytes()).to_vec()
  }
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct TestHram {}
impl Hram<Secp256k1> for TestHram {
  #[allow(non_snake_case)]
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    Scalar::from_uint_reduced(
      U512::from_be_byte_array(
        Sha512::new()
          .chain_update(Secp256k1::G_to_bytes(R))
          .chain_update(Secp256k1::G_to_bytes(A))
          .chain_update(m)
          .finalize()
      )
    )
  }
}

#[test]
fn secp256k1_curve() {
  test_curve::<_, Secp256k1>(&mut OsRng);
}
