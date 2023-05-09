use zeroize::Zeroize;

use digest::{
  typenum::U114, core_api::BlockSizeUser, Update, Output, OutputSizeUser, FixedOutput,
  ExtendableOutput, XofReader, HashMarker, Digest,
};
use sha3::Shake256;

use group::Group;
use minimal_ed448::{Scalar, Point};

use crate::Ciphersuite;

/// Shake256, fixed to a 114-byte output, as used by Ed448.
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

/// Ciphersuite for Ed448, inspired by RFC-8032. This is not recommended for usage.
///
/// hash_to_F is implemented with a naive concatenation of the dst and data, allowing transposition
/// between the two. This means `dst: b"abc", data: b"def"`, will produce the same scalar as
/// `dst: "abcdef", data: b""`. Please use carefully, not letting dsts be substrings of each other.
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
    Scalar::wide_reduce(Self::H::digest([dst, data].concat()).as_ref().try_into().unwrap())
  }
}

#[test]
fn test_ed448() {
  use ff::PrimeField;

  ff_group_tests::group::test_prime_group_bits::<_, Point>(&mut rand_core::OsRng);

  // Ideally, a test vector from RFC-8032 (not FROST) would be here
  // Unfortunately, the IETF draft doesn't provide any vectors for the derived challenges
  assert_eq!(
    Ed448::hash_to_F(
      b"FROST-ED448-SHAKE256-v11nonce",
      &hex::decode(
        "\
89bf16040081ff2990336b200613787937ebe1f024b8cdff90eb6f1c741d91c1\
4a2b2f5858a932ad3d3b18bd16e76ced3070d72fd79ae4402df201f5\
25e754716a1bc1b87a502297f2a99d89ea054e0018eb55d39562fd01\
00"
      )
      .unwrap()
    )
    .to_repr()
    .to_vec(),
    hex::decode(
      "\
67a6f023e77361707c6e894c625e809e80f33fdb310810053ae29e28\
e7011f3193b9020e73c183a98cc3a519160ed759376dd92c94831622\
00"
    )
    .unwrap()
  );
}
