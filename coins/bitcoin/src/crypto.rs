use sha2::{Digest, Sha256};
use frost::{algorithm::Hram, curve::Secp256k1};
use k256::{
  elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, sec1::Tag},
  ProjectivePoint, U256, Scalar,sha2::digest::generic_array::GenericArray,
  sha2::digest::generic_array::typenum::U32,
};

use lazy_static::lazy_static;

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
  static ref TAG_HASH : GenericArray<u8, U32> = Sha256::digest(b"BIP0340/challenge");
}

#[allow(clippy::non_snake_case)]
impl Hram<Secp256k1> for BitcoinHram {
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    let (R, _) = make_even(*R);

    let r_encoded_point = R.to_encoded_point(true);
    let a_encoded_point = A.to_encoded_point(true);
    //let tag_hash:GenericArray<u8, U32> = Sha256::digest(b"BIP0340/challenge");
    let mut data = Sha256::new();
    //data.update(TAG_HASH.as_ref());
    data.update(&*TAG_HASH);
    data.update(&*TAG_HASH);
    data.update(r_encoded_point.x().unwrap());
    data.update(a_encoded_point.x().unwrap());
    data.update(m);

    Scalar::from_uint_reduced(U256::from_be_slice(&data.finalize()))
  }
}
