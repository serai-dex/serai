use k256::{
  elliptic_curve::{bigint::ArrayEncoding, ops::Reduce, sec1::ToEncodedPoint},
  ProjectivePoint, Scalar, U256,
};
use frost::curve::Secp256k1;

use ethereum_serai::crypto::*;

#[test]
fn test_ecrecover() {
  use rand_core::OsRng;
  use sha2::Sha256;
  use sha3::{Digest, Keccak256};
  use k256::ecdsa::{hazmat::SignPrimitive, signature::DigestVerifier, SigningKey, VerifyingKey};

  let private = SigningKey::random(&mut OsRng);
  let public = VerifyingKey::from(&private);

  const MESSAGE: &[u8] = b"Hello, World!";
  let (sig, recovery_id) = private
    .as_nonzero_scalar()
    .try_sign_prehashed_rfc6979::<Sha256>(Keccak256::digest(MESSAGE), b"")
    .unwrap();
  assert_eq!(public.verify_digest(Keccak256::new_with_prefix(MESSAGE), &sig).unwrap(), ());

  assert_eq!(
    ecrecover(hash_to_scalar(MESSAGE), recovery_id.unwrap().is_y_odd().into(), *sig.r(), *sig.s())
      .unwrap(),
    address(&ProjectivePoint::from(public.as_affine()))
  );
}

#[test]
fn test_signing() {
  use frost::{
    algorithm::Schnorr,
    tests::{algorithm_machines, key_gen, sign},
  };
  use rand_core::OsRng;

  let keys = key_gen::<_, Secp256k1>(&mut OsRng);
  let _group_key = keys[&1].group_key();

  const MESSAGE: &[u8] = b"Hello, World!";

  let algo = Schnorr::<Secp256k1, EthereumHram>::new();
  let _sig = sign(
    &mut OsRng,
    algo,
    keys.clone(),
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, EthereumHram>::new(), &keys),
    MESSAGE,
  );
}

#[test]
fn test_ecrecover_hack() {
  use frost::{
    algorithm::Schnorr,
    tests::{algorithm_machines, key_gen, sign},
  };
  use rand_core::OsRng;

  let keys = key_gen::<_, Secp256k1>(&mut OsRng);
  let group_key = keys[&1].group_key();
  let group_key_encoded = group_key.to_encoded_point(true);
  let group_key_compressed = group_key_encoded.as_ref();
  let group_key_x = Scalar::from_uint_reduced(U256::from_be_slice(&group_key_compressed[1 .. 33]));

  const MESSAGE: &[u8] = b"Hello, World!";
  let hashed_message = keccak256(MESSAGE);
  let chain_id = U256::ONE;

  let full_message = &[chain_id.to_be_byte_array().as_slice(), &hashed_message].concat();

  let algo = Schnorr::<Secp256k1, EthereumHram>::new();
  let sig = sign(
    &mut OsRng,
    algo.clone(),
    keys.clone(),
    algorithm_machines(&mut OsRng, algo, &keys),
    full_message,
  );

  let (sr, er) =
    preprocess_signature_for_ecrecover(hashed_message, &sig.R, sig.s, &group_key, chain_id);
  let q = ecrecover(sr, group_key_compressed[0] - 2, group_key_x, er).unwrap();
  assert_eq!(q, address(&sig.R));
}
