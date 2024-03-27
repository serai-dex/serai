use sha3::{Digest, Keccak256};

use group::ff::PrimeField;
use k256::{
  elliptic_curve::{
    bigint::ArrayEncoding, ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint,
  },
  ProjectivePoint, Scalar, U256,
};

use frost::{
  algorithm::{Hram, SchnorrSignature},
  curve::Secp256k1,
};

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
  Keccak256::digest(data).into()
}

pub(crate) fn address(point: &ProjectivePoint) -> [u8; 20] {
  let encoded_point = point.to_encoded_point(false);
  // Last 20 bytes of the hash of the concatenated x and y coordinates
  // We obtain the concatenated x and y coordinates via the uncompressed encoding of the point
  keccak256(&encoded_point.as_ref()[1 .. 65])[12 ..].try_into().unwrap()
}

#[allow(non_snake_case)]
pub struct PublicKey {
  pub A: ProjectivePoint,
  pub px: Scalar,
  pub parity: u8,
}

impl PublicKey {
  #[allow(non_snake_case)]
  pub fn new(A: ProjectivePoint) -> Option<PublicKey> {
    let affine = A.to_affine();
    let parity = u8::from(bool::from(affine.y_is_odd())) + 27;
    if parity != 27 {
      None?;
    }

    let x_coord = affine.x();
    let x_coord_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&x_coord);
    // Return None if a reduction would occur
    if x_coord_scalar.to_repr() != x_coord {
      None?;
    }

    Some(PublicKey { A, px: x_coord_scalar, parity })
  }
}

#[derive(Clone, Default)]
pub struct EthereumHram {}
impl Hram<Secp256k1> for EthereumHram {
  #[allow(non_snake_case)]
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    let a_encoded_point = A.to_encoded_point(true);
    let mut a_encoded = a_encoded_point.as_ref().to_owned();
    a_encoded[0] += 25; // Ethereum uses 27/28 for point parity
    assert!((a_encoded[0] == 27) || (a_encoded[0] == 28));
    let mut data = address(R).to_vec();
    data.append(&mut a_encoded);
    data.extend(m);
    Scalar::reduce(U256::from_be_slice(&keccak256(&data)))
  }
}

pub struct Signature {
  pub(crate) c: Scalar,
  pub(crate) s: Scalar,
}
impl Signature {
  pub fn new(
    public_key: &PublicKey,
    chain_id: U256,
    m: &[u8],
    signature: SchnorrSignature<Secp256k1>,
  ) -> Option<Signature> {
    let c = EthereumHram::hram(
      &signature.R,
      &public_key.A,
      &[chain_id.to_be_byte_array().as_slice(), &keccak256(m)].concat(),
    );
    if !signature.verify(public_key.A, c) {
      None?;
    }
    Some(Signature { c, s: signature.s })
  }
}
