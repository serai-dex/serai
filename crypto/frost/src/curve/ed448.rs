use digest::Digest;

use minimal_ed448::{Scalar, Point};
pub use ciphersuite::{group::GroupEncoding, Shake256_114, Ed448};

use crate::{curve::Curve, algorithm::Hram};

const CONTEXT: &[u8] = b"FROST-ED448-SHAKE256-v11";

impl Curve for Ed448 {
  const CONTEXT: &'static [u8] = CONTEXT;
}

#[derive(Copy, Clone)]
pub struct Ietf8032Ed448Hram;
impl Ietf8032Ed448Hram {
  #[allow(non_snake_case)]
  pub fn hram(context: &[u8], R: &Point, A: &Point, m: &[u8]) -> Scalar {
    Scalar::wide_reduce(
      Shake256_114::digest(
        [
          &[b"SigEd448".as_ref(), &[0, u8::try_from(context.len()).unwrap()]].concat(),
          context,
          &[R.to_bytes().as_ref(), A.to_bytes().as_ref(), m].concat(),
        ]
        .concat(),
      )
      .as_ref()
      .try_into()
      .unwrap(),
    )
  }
}

#[derive(Copy, Clone)]
pub struct IetfEd448Hram;
impl Hram<Ed448> for IetfEd448Hram {
  #[allow(non_snake_case)]
  fn hram(R: &Point, A: &Point, m: &[u8]) -> Scalar {
    Ietf8032Ed448Hram::hram(&[], R, A, m)
  }
}
