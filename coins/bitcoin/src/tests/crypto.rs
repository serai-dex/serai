use rand_core::OsRng;

use sha2::{Digest, Sha256};

use secp256k1::{Secp256k1 as BContext, Message};

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

  for (_, keys) in keys.iter_mut() {
    let (_, offset) = make_even(keys.group_key());
    *keys = keys.offset(Scalar::from(offset));
  }

  let algo =
    Schnorr::<RecommendedTranscript>::new(RecommendedTranscript::new(b"bitcoin-serai sign test"));
  let sig = sign(
    &mut OsRng,
    algo.clone(),
    keys.clone(),
    algorithm_machines(&mut OsRng, algo, &keys),
    &Sha256::digest(MESSAGE),
  );

  BContext::new()
    .verify_schnorr(
      &sig,
      &Message::from(Hash::hash(MESSAGE)),
      &x_only(&keys[&Participant::new(1).unwrap()].group_key()),
    )
    .unwrap()
}
