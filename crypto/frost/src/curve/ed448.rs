use zeroize::Zeroize;

use digest::{
  typenum::U114, Update, Output, OutputSizeUser, FixedOutput, ExtendableOutput, XofReader,
  HashMarker, Digest,
};
use sha3::Shake256;

use group::{Group, GroupEncoding};
use minimal_ed448::{scalar::Scalar, point::Point};

use crate::{curve::Curve, algorithm::Hram};

const CONTEXT: &[u8] = b"FROST-ED448-SHAKE256-v11";

// Re-define Shake256 as a traditional Digest to meet API expectations
#[derive(Default)]
pub struct Shake256_114(Shake256);
impl OutputSizeUser for Shake256_114 {
  type OutputSize = U114;
  fn output_size() -> usize {
    114
  }
}
impl Update for Shake256_114 {
  fn update(&mut self, data: &[u8]) {
    self.0.update(data);
  }
  fn chain(mut self, data: impl AsRef<[u8]>) -> Self {
    Update::update(&mut self, data.as_ref());
    self
  }
}
impl FixedOutput for Shake256_114 {
  fn finalize_fixed(self) -> Output<Self> {
    let mut res = Default::default();
    FixedOutput::finalize_into(self, &mut res);
    res
  }
  fn finalize_into(self, out: &mut Output<Self>) {
    let mut reader = self.0.finalize_xof();
    reader.read(out);
  }
}
impl HashMarker for Shake256_114 {}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Ed448;
impl Curve for Ed448 {
  type F = Scalar;
  type G = Point;
  type H = Shake256_114;

  const ID: &'static [u8] = b"ed448";
  const CONTEXT: &'static [u8] = CONTEXT;

  fn generator() -> Self::G {
    Point::generator()
  }

  fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
    Scalar::wide_reduce(Self::hash_to_vec(dst, data).try_into().unwrap())
  }
}

#[derive(Copy, Clone)]
pub struct Ietf8032Ed448Hram;
impl Ietf8032Ed448Hram {
  #[allow(non_snake_case)]
  pub fn hram(context: &[u8], R: &Point, A: &Point, m: &[u8]) -> Scalar {
    Scalar::wide_reduce(
      Shake256_114::digest(
        &[
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
