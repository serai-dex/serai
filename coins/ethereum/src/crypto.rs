use sha3::{Digest, Keccak256};

use group::Group;
use k256::{
  elliptic_curve::{
    bigint::ArrayEncoding, ops::Reduce, point::DecompressPoint, sec1::ToEncodedPoint,
  },
  AffinePoint, ProjectivePoint, Scalar, U256,
};

use frost::{algorithm::Hram, curve::Secp256k1};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
  Keccak256::digest(data).try_into().unwrap()
}

pub fn hash_to_scalar(data: &[u8]) -> Scalar {
  Scalar::reduce(U256::from_be_slice(&keccak256(data)))
}

pub fn address(point: &ProjectivePoint) -> [u8; 20] {
  let encoded_point = point.to_encoded_point(false);
  keccak256(&encoded_point.as_ref()[1 .. 65])[12 .. 32].try_into().unwrap()
}

pub fn ecrecover(message: Scalar, v: u8, r: Scalar, s: Scalar) -> Option<[u8; 20]> {
  if r.is_zero().into() || s.is_zero().into() {
    return None;
  }

  #[allow(non_snake_case)]
  let R = AffinePoint::decompress(&r.to_bytes(), v.into());
  #[allow(non_snake_case)]
  if let Some(R) = Option::<AffinePoint>::from(R) {
    #[allow(non_snake_case)]
    let R = ProjectivePoint::from(R);

    let r = r.invert().unwrap();
    let u1 = ProjectivePoint::GENERATOR * (-message * r);
    let u2 = R * (s * r);
    let key: ProjectivePoint = u1 + u2;
    if !bool::from(key.is_identity()) {
      return Some(address(&key));
    }
  }

  None
}

#[derive(Clone, Default)]
pub struct EthereumHram {}
impl Hram<Secp256k1> for EthereumHram {
  #[allow(non_snake_case)]
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    let a_encoded_point = A.to_encoded_point(true);
    let mut a_encoded = a_encoded_point.as_ref().to_owned();
    a_encoded[0] += 25; // Ethereum uses 27/28 for point parity
    let mut data = address(R).to_vec();
    data.append(&mut a_encoded);
    data.append(&mut m.to_vec());
    Scalar::reduce(U256::from_be_slice(&keccak256(&data)))
  }
}

pub struct ProcessedSignature {
  pub s: Scalar,
  pub px: Scalar,
  pub parity: u8,
  pub message: [u8; 32],
  pub e: Scalar,
}

#[allow(non_snake_case)]
pub fn preprocess_signature_for_ecrecover(
  m: [u8; 32],
  R: &ProjectivePoint,
  s: Scalar,
  A: &ProjectivePoint,
  chain_id: U256,
) -> (Scalar, Scalar) {
  let processed_sig = process_signature_for_contract(m, R, s, A, chain_id);
  let sr = processed_sig.s.mul(&processed_sig.px).negate();
  let er = processed_sig.e.mul(&processed_sig.px).negate();
  (sr, er)
}

#[allow(non_snake_case)]
pub fn process_signature_for_contract(
  m: [u8; 32],
  R: &ProjectivePoint,
  s: Scalar,
  A: &ProjectivePoint,
  chain_id: U256,
) -> ProcessedSignature {
  let encoded_pk = A.to_encoded_point(true);
  let px = &encoded_pk.as_ref()[1 .. 33];
  let px_scalar = Scalar::reduce(U256::from_be_slice(px));
  let e = EthereumHram::hram(R, A, &[chain_id.to_be_byte_array().as_slice(), &m].concat());
  ProcessedSignature {
    s,
    px: px_scalar,
    parity: &encoded_pk.as_ref()[0] - 2,
    #[allow(non_snake_case)]
    message: m,
    e,
  }
}
