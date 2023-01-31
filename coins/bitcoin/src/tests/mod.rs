use rand_core::OsRng;

use sha2::{Digest, Sha256};

use secp256k1::{SECP256K1, Message, schnorr::Signature};
use bitcoin::hashes::{Hash as HashTrait, sha256::Hash};

use k256::Scalar;
use frost::{
  curve::Secp256k1,
  algorithm::Schnorr,
  tests::{algorithm_machines, key_gen, sign},
};

use crate::crypto::{BitcoinHram, x_only, make_even};

#[test]
fn test_signing() {
  let mut keys = key_gen::<_, Secp256k1>(&mut OsRng);
  const MESSAGE: &[u8] = b"Hello, World!";

  for (_, keys) in keys.iter_mut() {
    let (_, offset) = make_even(keys.group_key());
    *keys = keys.offset(Scalar::from(offset));
  }

  let algo = Schnorr::<Secp256k1, BitcoinHram>::new();
  let mut sig = sign(
    &mut OsRng,
    algo,
    keys.clone(),
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, BitcoinHram>::new(), &keys),
    &Sha256::digest(MESSAGE),
  );

  let offset;
  (sig.R, offset) = make_even(sig.R);
  sig.s += Scalar::from(offset);

  SECP256K1
    .verify_schnorr(
      &Signature::from_slice(&sig.serialize()[1 .. 65]).unwrap(),
      &Message::from(Hash::hash(MESSAGE)),
      &x_only(&keys[&1].group_key()),
    )
    .unwrap()
}
