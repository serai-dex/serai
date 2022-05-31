use core::convert::TryInto;

use ff::PrimeField;
use group::GroupEncoding;

use sha2::{Digest, Sha256, Sha512};

use k256::{
  elliptic_curve::{generic_array::GenericArray, bigint::{ArrayEncoding, U512}, ops::Reduce},
  Scalar,
  ProjectivePoint
};

use transcript::DigestTranscript;
use frost::{CurveError, Curve};

use crate::spark::G;

const CONTEXT: &[u8] = b"FROST-K256-SHA";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Secp256k1;
impl Curve for Secp256k1 {
  type F = Scalar;
  type G = ProjectivePoint;
  type T = ProjectivePoint;

  fn id() -> String {
    "secp256k1".to_string()
  }

  fn id_len() -> u8 {
    u8::try_from(Self::id().len()).unwrap()
  }

  fn generator() -> Self::G {
    *G
  }

  fn generator_table() -> Self::T {
    *G
  }

  fn little_endian() -> bool {
    false
  }

  // The IETF draft doesn't specify a secp256k1 ciphersuite
  // This test just uses the simplest ciphersuite which would still be viable to deploy
  // The comparable P-256 curve uses hash_to_field from the Hash To Curve IETF draft with a context
  // string and further DST for H1 ("rho") and H3 ("digest"). With lack of hash_to_field, wide
  // reduction is used
  fn hash_msg(msg: &[u8]) -> Vec<u8> {
    (&Sha256::digest(&[CONTEXT, b"digest", msg].concat())).to_vec()
  }

  fn hash_binding_factor(binding: &[u8]) -> Self::F {
    Self::hash_to_F(&[CONTEXT, b"rho", binding].concat())
  }

  fn hash_to_F(data: &[u8]) -> Self::F {
    Scalar::from_uint_reduced(U512::from_be_byte_array(Sha512::digest(data)))
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

pub type Transcript = DigestTranscript::<blake2::Blake2b512>;
