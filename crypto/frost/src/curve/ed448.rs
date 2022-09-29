use zeroize::Zeroize;

use sha3::{digest::ExtendableOutput, Shake256};

use group::{Group, GroupEncoding};
use minimal_ed448::{scalar::Scalar, point::Point};

use crate::{curve::Curve, algorithm::Hram};

const CONTEXT: &[u8] = b"FROST-ED448-SHAKE256-v10";

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Ed448;
impl Ed448 {
  fn hash(prefix: &[u8], context: &[u8], dst: &[u8], data: &[u8]) -> [u8; 114] {
    let mut res = [0; 114];
    Shake256::digest_xof(&[prefix, context, dst, data].concat(), &mut res);
    res
  }
}

impl Curve for Ed448 {
  type F = Scalar;
  type G = Point;

  const ID: &'static [u8] = b"ed448";

  fn generator() -> Self::G {
    Point::generator()
  }

  fn hash_to_vec(dst: &[u8], data: &[u8]) -> Vec<u8> {
    Self::hash(b"", CONTEXT, dst, data).as_ref().to_vec()
  }

  fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
    Scalar::wide_reduce(Self::hash(b"", CONTEXT, dst, data))
  }
}

#[derive(Copy, Clone)]
pub struct Ietf8032Ed448Hram;
impl Ietf8032Ed448Hram {
  #[allow(non_snake_case)]
  pub fn hram(context: &[u8], R: &Point, A: &Point, m: &[u8]) -> Scalar {
    Scalar::wide_reduce(Ed448::hash(
      &[b"SigEd448".as_ref(), &[0, u8::try_from(context.len()).unwrap()]].concat(),
      context,
      b"",
      &[R.to_bytes().as_ref(), A.to_bytes().as_ref(), m].concat(),
    ))
  }
}

#[derive(Copy, Clone)]
pub struct NonIetfEd448Hram;
impl Hram<Ed448> for NonIetfEd448Hram {
  #[allow(non_snake_case)]
  fn hram(R: &Point, A: &Point, m: &[u8]) -> Scalar {
    Ietf8032Ed448Hram::hram(&[], R, A, m)
  }
}
