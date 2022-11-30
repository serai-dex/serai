#[test]
fn test_signing() {
  use secp256k1::Message;
  use bitcoin_hashes::{sha256, Hash};
  use frost::{
    curve::Secp256k1,
    algorithm::Schnorr,
    tests::{algorithm_machines, key_gen, sign},
  };
  use sha2::{Digest, Sha256};
  use rand_core::OsRng;
  use bitcoin_serai::crypto::{BitcoinHram, make_even};
  use k256::{elliptic_curve::sec1::ToEncodedPoint,Scalar};

  let mut keys = key_gen::<_, Secp256k1>(&mut OsRng);
  const MESSAGE: &'static [u8] = b"Hello, World!";

  for (_, one_key) in keys.iter_mut() {
    let (_, offset) = make_even(one_key.group_key());
    *one_key = one_key.offset(Scalar::from(offset));
  }

  let mut _sig = sign(
    &mut OsRng,
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, BitcoinHram>::new(), &keys), //&keys),
    &Sha256::digest(MESSAGE),
  );
  
  let mut offset = 0;
  (_sig.R, offset) = make_even(_sig.R);
  _sig.s += Scalar::from(offset);

  let sig = secp256k1::schnorr::Signature::from_slice(&_sig.serialize()[1..65]).unwrap();
  let msg = Message::from(sha256::Hash::hash(&MESSAGE));
  let pubkey_compressed = &keys[&1].group_key().to_encoded_point(true);
  let pubkey =
    secp256k1::XOnlyPublicKey::from_slice(&pubkey_compressed.x().to_owned().unwrap()).unwrap();
  let _res = sig.verify(&msg, &pubkey).unwrap();
}
