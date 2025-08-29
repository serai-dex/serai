pub use ciphersuite::{digest::Digest, group::GroupEncoding, FromUniformBytes, Ciphersuite};
use minimal_ed448::{Scalar, Point};
pub use minimal_ed448::Ed448;

use crate::{curve::Curve, algorithm::Hram};

const CONTEXT: &[u8] = b"FROST-ED448-SHAKE256-v1";

impl Curve for Ed448 {
  const CONTEXT: &'static [u8] = CONTEXT;
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
    let mut digest = <Self as Ciphersuite>::H::new();
    digest.update(Self::CONTEXT);
    digest.update(dst);
    digest.update(msg);
    Self::F::from_uniform_bytes(&digest.finalize().into())
  }
}

// The RFC-8032 Ed448 challenge function.
#[derive(Copy, Clone)]
pub(crate) struct Ietf8032Ed448Hram;
impl Ietf8032Ed448Hram {
  #[allow(non_snake_case)]
  pub(crate) fn hram(context: &[u8], R: &Point, A: &Point, m: &[u8]) -> Scalar {
    let mut digest = <Ed448 as Ciphersuite>::H::new();
    digest.update(b"SigEd448");
    digest.update([0, u8::try_from(context.len()).unwrap()]);
    digest.update(context);
    digest.update(R.to_bytes());
    digest.update(A.to_bytes());
    digest.update(m);
    Scalar::from_uniform_bytes(&digest.finalize().into())
  }
}

/// The challenge function for FROST's Ed448 ciphersuite.
#[derive(Copy, Clone)]
pub struct IetfEd448Hram;
impl Hram<Ed448> for IetfEd448Hram {
  #[allow(non_snake_case)]
  fn hram(R: &Point, A: &Point, m: &[u8]) -> Scalar {
    Ietf8032Ed448Hram::hram(&[], R, A, m)
  }
}
