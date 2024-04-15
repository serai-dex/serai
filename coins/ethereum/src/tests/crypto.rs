use rand_core::OsRng;

use sha2::Sha256;
use sha3::{Digest, Keccak256};

use group::Group;
use k256::{
  ecdsa::{hazmat::SignPrimitive, signature::DigestVerifier, SigningKey, VerifyingKey},
  elliptic_curve::point::DecompressPoint,
  Scalar, AffinePoint, ProjectivePoint,
};

use frost::{
  curve::Secp256k1,
  algorithm::{Hram, IetfSchnorr},
  tests::{algorithm_machines, sign},
};

use crate::{crypto::*, tests::key_gen};

// The ecrecover opcode, yet with parity replacing v
// This didn't use the ecrecover from ethers-core due to that enforcing a low-s bound which is
// invalid for our use case
// alloy doesn't appear to expose a function offering the ecrecover behavior
pub(crate) fn ecrecover(message: Scalar, parity: u8, r: Scalar, s: Scalar) -> Option<[u8; 20]> {
  if r.is_zero().into() || s.is_zero().into() || !((parity == 0) || (parity == 1)) {
    return None;
  }

  #[allow(non_snake_case)]
  let R = AffinePoint::decompress(&r.to_bytes(), parity.into());
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

#[test]
fn test_ecrecover() {
  let private = SigningKey::random(&mut OsRng);
  let public = VerifyingKey::from(&private);

  // Sign the signature
  const MESSAGE: &[u8] = b"Hello, World!";
  let (sig, recovery_id) = private
    .as_nonzero_scalar()
    .try_sign_prehashed_rfc6979::<Sha256>(&Keccak256::digest(MESSAGE), b"")
    .unwrap();

  // Sanity check the signature verifies
  #[allow(clippy::unit_cmp)] // Intended to assert this wasn't changed to Result<bool>
  {
    assert_eq!(public.verify_digest(Keccak256::new_with_prefix(MESSAGE), &sig).unwrap(), ());
  }

  // Perform the ecrecover
  assert_eq!(
    ecrecover(
      hash_to_scalar(MESSAGE),
      u8::from(recovery_id.unwrap().is_y_odd()),
      *sig.r(),
      *sig.s()
    )
    .unwrap(),
    address(&ProjectivePoint::from(public.as_affine()))
  );
}

// Run the sign test with the EthereumHram
#[test]
fn test_signing() {
  let (keys, _) = key_gen();

  const MESSAGE: &[u8] = b"Hello, World!";

  let algo = IetfSchnorr::<Secp256k1, EthereumHram>::ietf();
  let _sig =
    sign(&mut OsRng, &algo, keys.clone(), algorithm_machines(&mut OsRng, &algo, &keys), MESSAGE);
}

#[allow(non_snake_case)]
pub fn preprocess_signature_for_ecrecover(
  R: ProjectivePoint,
  public_key: &PublicKey,
  m: &[u8],
  s: Scalar,
) -> (Scalar, Scalar) {
  let c = EthereumHram::hram(&R, &public_key.A, m);
  let sa = -(s * public_key.px);
  let ca = -(c * public_key.px);
  (sa, ca)
}

#[test]
fn test_ecrecover_hack() {
  let (keys, public_key) = key_gen();

  const MESSAGE: &[u8] = b"Hello, World!";

  let algo = IetfSchnorr::<Secp256k1, EthereumHram>::ietf();
  let sig =
    sign(&mut OsRng, &algo, keys.clone(), algorithm_machines(&mut OsRng, &algo, &keys), MESSAGE);

  let (sa, ca) = preprocess_signature_for_ecrecover(sig.R, &public_key, MESSAGE, sig.s);
  let q = ecrecover(sa, 0, public_key.px, ca).unwrap();
  assert_eq!(q, address(&sig.R));
}
