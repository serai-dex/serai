use rand_core::OsRng;

use sha2::{Digest, Sha256};

use secp256k1::{SECP256K1, XOnlyPublicKey, Message, schnorr::Signature};
use bitcoin::hashes::{sha256, Hash};

use k256::{elliptic_curve::sec1::ToEncodedPoint, Scalar};
use frost::{
  curve::Secp256k1,
  algorithm::Schnorr,
  tests::{algorithm_machines, key_gen, sign},
};

use bitcoin_serai::crypto::{BitcoinHram, make_even};

#[test]
fn test_signing() {
  let mut keys = key_gen::<_, Secp256k1>(&mut OsRng);
  const MESSAGE: &[u8] = b"Hello, World!";

  for (_, one_key) in keys.iter_mut() {
    let (_, offset) = make_even(one_key.group_key());
    *one_key = one_key.offset(Scalar::from(offset));
  }

  let algo = Schnorr::<Secp256k1, BitcoinHram>::new();
  let mut _sig = sign(
    &mut OsRng,
    algo,
    keys.clone(),
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, BitcoinHram>::new(), &keys),
    &Sha256::digest(MESSAGE),
  );

  let mut _offset = 0;
  (_sig.R, _offset) = make_even(_sig.R);
  _sig.s += Scalar::from(_offset);

  let sig = Signature::from_slice(&_sig.serialize()[1 .. 65]).unwrap();
  let msg = Message::from(sha256::Hash::hash(MESSAGE));
  let pubkey_compressed = keys[&1].group_key().to_encoded_point(true);
  let pubkey = XOnlyPublicKey::from_slice(pubkey_compressed.x().to_owned().unwrap()).unwrap();
  SECP256K1.verify_schnorr(&sig, &msg, &pubkey).unwrap()
}
