use lazy_static::lazy_static;

use sha2::{Digest, Sha256};

use k256::{
  elliptic_curve::{
    ops::Reduce,
    sec1::{Tag, ToEncodedPoint},
  },
  U256, Scalar, ProjectivePoint,
};
use frost::{algorithm::Hram, curve::Secp256k1};

pub fn make_even(mut key: ProjectivePoint) -> (ProjectivePoint, u64) {
  let mut c = 0;
  while key.to_encoded_point(true).tag() == Tag::CompressedOddY {
    key += ProjectivePoint::GENERATOR;
    c += 1;
  }
  (key, c)
}

#[derive(Clone)]
pub struct BitcoinHram {}

lazy_static! {
  static ref TAG_HASH: [u8; 32] = Sha256::digest(b"BIP0340/challenge").into();
}

#[allow(non_snake_case)]
impl Hram<Secp256k1> for BitcoinHram {
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    let (R, _) = make_even(*R);

    let mut data = Sha256::new();
    data.update(*TAG_HASH);
    data.update(*TAG_HASH);
    data.update(R.to_encoded_point(true).x().unwrap());
    data.update(A.to_encoded_point(true).x().unwrap());
    data.update(m);

    Scalar::from_uint_reduced(U256::from_be_slice(&data.finalize()))
  }
}
