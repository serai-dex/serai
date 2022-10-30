use zeroize::Zeroize;

use digest::{
  typenum::U114, core_api::BlockSizeUser, Update, Output, OutputSizeUser, FixedOutput,
  ExtendableOutput, XofReader, HashMarker, Digest,
};
use sha3::Shake256;

use group::Group;
use minimal_ed448::{scalar::Scalar, point::Point};

use crate::Ciphersuite;

// Re-define Shake256 as a traditional Digest to meet API expectations
#[derive(Clone, Default)]
pub struct Shake256_114(Shake256);
impl BlockSizeUser for Shake256_114 {
  type BlockSize = <Shake256 as BlockSizeUser>::BlockSize;
  fn block_size() -> usize {
    Shake256::block_size()
  }
}
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
impl Ciphersuite for Ed448 {
  type F = Scalar;
  type G = Point;
  type H = Shake256_114;

  const ID: &'static [u8] = b"ed448";

  fn generator() -> Self::G {
    Point::generator()
  }

  fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
    Scalar::wide_reduce(Self::H::digest(&[dst, data].concat()).as_ref().try_into().unwrap())
  }
}
