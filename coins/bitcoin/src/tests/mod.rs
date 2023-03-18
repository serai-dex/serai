use rand_core::OsRng;

use sha2::{Digest, Sha256};

use secp256k1::{SECP256K1, Message};
use bitcoin::hashes::{Hash as HashTrait, sha256::Hash};

use k256::Scalar;
use transcript::{Transcript, RecommendedTranscript};
use frost::{
  curve::Secp256k1,
  Participant,
  tests::{algorithm_machines, key_gen, sign},
};

use crate::{
  crypto::{x_only, make_even},
  algorithm::Schnorr,
  rpc::Rpc,
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

  SECP256K1
    .verify_schnorr(
      &sig,
      &Message::from(Hash::hash(MESSAGE)),
      &x_only(&keys[&Participant::new(1).unwrap()].group_key()),
    )
    .unwrap()
}

#[tokio::test]
async fn test_rpc() {
  let rpc = Rpc::new("http://serai:seraidex@127.0.0.1:18443".to_string()).await.unwrap();

  let latest = rpc.get_latest_block_number().await.unwrap();
  assert_eq!(
    rpc.get_block_number(&rpc.get_block_hash(latest).await.unwrap()).await.unwrap(),
    latest
  );
}
