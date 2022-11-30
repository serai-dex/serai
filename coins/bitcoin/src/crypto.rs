use sha2::{Digest, Sha256};
use frost::{algorithm::Hram, curve::Secp256k1};
use k256::{
  elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, sec1::Tag},
  ProjectivePoint, U256, Scalar,
};

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

impl Hram<Secp256k1> for BitcoinHram {
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    let (R, _) = make_even(*R);

    let r_encoded_point = R.to_encoded_point(true);
    let a_encoded_point = A.to_encoded_point(true);
    let tag = b"BIP0340/challenge";
    let tag_hash = Sha256::digest(tag);
    let mut data = Sha256::new();
    data.update(tag_hash);
    data.update(tag_hash);
    data.update(r_encoded_point.x().to_owned().unwrap());
    data.update(a_encoded_point.x().to_owned().unwrap());
    data.update(&m[..]);

    Scalar::from_uint_reduced(U256::from_be_slice(&data.finalize()))
  }
}
