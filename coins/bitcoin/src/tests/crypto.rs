use rand_core::OsRng;

use secp256k1::{Secp256k1 as BContext, Message, schnorr::Signature};

use k256::Scalar;
use transcript::{Transcript, RecommendedTranscript};
use frost::{
  curve::Secp256k1,
  Participant,
  tests::{algorithm_machines, key_gen, sign},
};

use crate::{
  bitcoin::hashes::{Hash as HashTrait, sha256::Hash},
  crypto::{x_only, make_even, Schnorr},
};

#[test]
fn test_algorithm() {
  let mut keys = key_gen::<_, Secp256k1>(&mut OsRng);
  const MESSAGE: &[u8] = b"Hello, World!";

  for keys in keys.values_mut() {
    let (_, offset) = make_even(keys.group_key());
    *keys = keys.offset(Scalar::from(offset));
  }

  let algo =
    Schnorr::<RecommendedTranscript>::new(RecommendedTranscript::new(b"bitcoin-serai sign test"));
  let sig = sign(
    &mut OsRng,
    &algo,
    keys.clone(),
    algorithm_machines(&mut OsRng, &algo, &keys),
    Hash::hash(MESSAGE).as_ref(),
  );

  BContext::new()
    .verify_schnorr(
      &Signature::from_slice(&sig)
        .expect("couldn't convert produced signature to secp256k1::Signature"),
      &Message::from(Hash::hash(MESSAGE)),
      &x_only(&keys[&Participant::new(1).unwrap()].group_key()),
    )
    .unwrap()
}
