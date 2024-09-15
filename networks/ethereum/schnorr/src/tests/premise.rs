use rand_core::{RngCore, OsRng};

use sha3::{Digest, Keccak256};
use group::ff::{Field, PrimeField};
use k256::{
  elliptic_curve::{ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint},
  ecdsa::{
    self, hazmat::SignPrimitive, signature::hazmat::PrehashVerifier, SigningKey, VerifyingKey,
  },
  U256, Scalar, ProjectivePoint,
};

use alloy_core::primitives::Address;

use crate::{PublicKey, Signature};

// The ecrecover opcode, yet with if the y is odd replacing v
fn ecrecover(message: Scalar, odd_y: bool, r: Scalar, s: Scalar) -> Option<[u8; 20]> {
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

// Test ecrecover behaves as expected
#[test]
fn test_ecrecover() {
  let private = SigningKey::random(&mut OsRng);
  let public = VerifyingKey::from(&private);

  // Sign the signature
  const MESSAGE: &[u8] = b"Hello, World!";
  let (sig, recovery_id) = private
    .as_nonzero_scalar()
    .try_sign_prehashed(Scalar::random(&mut OsRng), &Keccak256::digest(MESSAGE))
    .unwrap();

  // Sanity check the signature verifies
  #[allow(clippy::unit_cmp)] // Intended to assert this wasn't changed to Result<bool>
  {
    assert_eq!(public.verify_prehash(&Keccak256::digest(MESSAGE), &sig).unwrap(), ());
  }

  // Perform the ecrecover
  assert_eq!(
    ecrecover(
      <Scalar as Reduce<U256>>::reduce_bytes(&Keccak256::digest(MESSAGE)),
      u8::from(recovery_id.unwrap().is_y_odd()) == 1,
      *sig.r(),
      *sig.s()
    )
    .unwrap(),
    Address::from_raw_public_key(&public.to_encoded_point(false).as_ref()[1 ..]),
  );
}

// Test that we can recover the nonce from a Schnorr signature via a call to ecrecover, the premise
// of efficiently verifying Schnorr signatures in an Ethereum contract
#[test]
fn nonce_recovery_via_ecrecover() {
  let (key, public_key) = loop {
    let key = Scalar::random(&mut OsRng);
    if let Some(public_key) = PublicKey::new(ProjectivePoint::GENERATOR * key) {
      break (key, public_key);
    }
  };

  let nonce = Scalar::random(&mut OsRng);
  let R = ProjectivePoint::GENERATOR * nonce;

  let mut message = vec![0; 1 + usize::try_from(OsRng.next_u32() % 256).unwrap()];
  OsRng.fill_bytes(&mut message);

  let c = Signature::challenge(R, &public_key, &message);
  let s = nonce + (c * key);

  /*
    An ECDSA signature is `(r, s)` with `s = (H(m) + rx) / k`, where:
    - `m` is the message
    - `r` is the x-coordinate of the nonce, reduced into a scalar
    - `x` is the private key
    - `k` is the nonce

    We fix the recovery ID to be for the even key with an x-coordinate < the order. Accordingly,
    `kG = Point::from(Even, r)`. This enables recovering the public key via
    `((s Point::from(Even, r)) - H(m)G) / r`.

    We want to calculate `R` from `(c, s)` where `s = r + cx`. That means we need to calculate
    `sG - cX`.

    We can calculate `sG - cX` with `((s Point::from(Even, r)) - H(m)G) / r` if:
    - Latter `r` = `X.x`
    - Latter `s` = `c`
    - `H(m)` = former `s`
    This gets us to `(cX - sG) / X.x`. If we additionally scale the latter's `s, H(m)` values (the
    former's `c, s` values) by `X.x`, we get `cX - sG`. This just requires negating each to achieve
    `sG - cX`.
  */
  let x_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&public_key.point().to_affine().x());
  let sa = -(s * x_scalar);
  let ca = -(c * x_scalar);

  let q = ecrecover(sa, false, x_scalar, ca).unwrap();
  assert_eq!(q, Address::from_raw_public_key(&R.to_encoded_point(false).as_ref()[1 ..]));
}
