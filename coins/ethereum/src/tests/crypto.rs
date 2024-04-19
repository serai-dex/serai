use rand_core::OsRng;

use group::ff::{Field, PrimeField};
use k256::{
  ecdsa::{
    self, hazmat::SignPrimitive, signature::hazmat::PrehashVerifier, SigningKey, VerifyingKey,
  },
  Scalar, ProjectivePoint,
};

use frost::{
  curve::{Ciphersuite, Secp256k1},
  algorithm::{Hram, IetfSchnorr},
  tests::{algorithm_machines, sign},
};

use crate::{crypto::*, tests::key_gen};

// The ecrecover opcode, yet with parity replacing v
pub(crate) fn ecrecover(message: Scalar, odd_y: bool, r: Scalar, s: Scalar) -> Option<[u8; 20]> {
  let sig = ecdsa::Signature::from_scalars(r, s).ok()?;
  let message: [u8; 32] = message.to_repr().into();
  alloy_core::primitives::Signature::from_signature_and_parity(
    sig,
    alloy_core::primitives::Parity::Parity(odd_y),
  )
  .ok()?
  .recover_address_from_prehash(&alloy_core::primitives::B256::from(message))
  .ok()
  .map(Into::into)
}

#[test]
fn test_ecrecover() {
  let private = SigningKey::random(&mut OsRng);
  let public = VerifyingKey::from(&private);

  // Sign the signature
  const MESSAGE: &[u8] = b"Hello, World!";
  let (sig, recovery_id) = private
    .as_nonzero_scalar()
    .try_sign_prehashed(
      <Secp256k1 as Ciphersuite>::F::random(&mut OsRng),
      &keccak256(MESSAGE).into(),
    )
    .unwrap();

  // Sanity check the signature verifies
  #[allow(clippy::unit_cmp)] // Intended to assert this wasn't changed to Result<bool>
  {
    assert_eq!(public.verify_prehash(&keccak256(MESSAGE), &sig).unwrap(), ());
  }

  // Perform the ecrecover
  assert_eq!(
    ecrecover(
      hash_to_scalar(MESSAGE),
      u8::from(recovery_id.unwrap().is_y_odd()) == 1,
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
  let q = ecrecover(sa, false, public_key.px, ca).unwrap();
  assert_eq!(q, address(&sig.R));
}
