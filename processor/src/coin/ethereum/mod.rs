use sha3::{Digest, Keccak256};

use group::Group;
use k256::{
  elliptic_curve::{ops::Reduce, DecompressPoint, sec1::ToEncodedPoint, bigint::ArrayEncoding},
  U256, Scalar, ProjectivePoint, AffinePoint
};

use frost::{curve::Secp256k1, algorithm::Hram};

fn keccak256(data: &[u8]) -> [u8; 32] {
  Keccak256::digest(data).try_into().unwrap()
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
  Scalar::from_uint_reduced(U256::from_be_slice(&keccak256(data)))
}

fn address(point: &ProjectivePoint) -> [u8; 20] {
  keccak256(point.to_encoded_point(false).as_ref())[0 .. 20].try_into().unwrap()
}

fn ecrecover(message: Scalar, v: u8, r: Scalar, s: Scalar) -> Option<[u8; 20]> {
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
  return None;
}

#[derive(Clone, Default)]
struct EthereumHram {}
impl Hram<Secp256k1> for EthereumHram {
  #[allow(non_snake_case)]
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    Scalar::from_uint_reduced(
      U256::from_be_slice(
        &keccak256(&[&address(R), A.to_encoded_point(true).as_ref(), m].concat())
      )
    )
  }
}

fn preprocess_signature(m: &[u8], R: &ProjectivePoint, s: Scalar, A: &ProjectivePoint, chain_id: U256) -> (Scalar, Scalar) {
  let encoded_pk = A.to_encoded_point(true);
  let px = &encoded_pk.as_ref()[1..33];
  let px_scalar = Scalar::from_uint_reduced(U256::from_be_slice(px));
  let e = EthereumHram::hram(R, A, &[chain_id.to_be_byte_array().as_slice(), m].concat());
  let sr = s.mul(&px_scalar).negate();
  let er = e.mul(&px_scalar).negate();
  (sr, er)
}

#[test]
fn test_ecrecover() {
  use rand::rngs::OsRng;
  use k256::{ecdsa::{SigningKey, VerifyingKey, recoverable::Signature, signature::{Signer, Verifier}}};

  let private = SigningKey::random(&mut OsRng);
  let public = VerifyingKey::from(&private);

  const MESSAGE: &'static [u8] = b"Hello, World!";
  let sig: Signature = private.sign(MESSAGE);
  public.verify(MESSAGE, &sig).unwrap();
  //assert!(verify(ProjectivePoint::from(public), MESSAGE, *sig.r(), *sig.s()));

  assert_eq!(
    ecrecover(hash_to_scalar(MESSAGE), sig.as_ref()[64], *sig.r(), *sig.s()).unwrap(),
    address(&ProjectivePoint::from(public))
  );
}

#[test]
fn test_signing() {
  use rand::rngs::OsRng;
  use frost::{algorithm::Schnorr, tests::{key_gen, algorithm_machines, sign}};

  let keys = key_gen::<_, Secp256k1>(&mut OsRng);
  let _group_key = keys[&1].group_key();

  const MESSAGE: &'static [u8] = b"Hello, World!";

  let _sig = sign(
    &mut OsRng,
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, EthereumHram>::new(), &keys),
    MESSAGE
  );
}

#[test]
fn test_ecrecover_hack() {
  use rand::rngs::OsRng;
  use frost::{algorithm::Schnorr, tests::{key_gen, algorithm_machines, sign}};

  let keys = key_gen::<_, Secp256k1>(&mut OsRng);
  let _group_key = keys[&1].group_key();

  const MESSAGE: &'static [u8] = b"Hello, World!";

  let sig = sign(
    &mut OsRng,
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, EthereumHram>::new(), &keys),
    MESSAGE
  );

  println!("{:?}", sig);
  // TODO
}