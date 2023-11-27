use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::OsRng;

use sp_core::{Pair, sr25519::Signature};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::dkg::musig::musig;
use schnorrkel::Schnorrkel;

use serai_client::{
  primitives::insecure_pair_from_name,
  validator_sets::{
    primitives::{ValidatorSet, KeyPair, musig_context, musig_key, set_keys_message},
    ValidatorSetsEvent,
  },
  SeraiValidatorSets, Serai,
};

use crate::common::tx::publish_tx;

#[allow(dead_code)]
pub async fn set_keys(serai: &Serai, set: ValidatorSet, key_pair: KeyPair) -> [u8; 32] {
  let pair = insecure_pair_from_name("Alice");
  let public = pair.public();

  let public_key = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut public.0.as_ref()).unwrap();
  assert_eq!(
    serai
      .as_of_latest_finalized_block()
      .await
      .unwrap()
      .validator_sets()
      .musig_key(set)
      .await
      .unwrap()
      .unwrap(),
    musig_key(set, &[public]).0
  );

  let secret_key = <Ristretto as Ciphersuite>::read_F::<&[u8]>(
    &mut pair.as_ref().secret.to_bytes()[.. 32].as_ref(),
  )
  .unwrap();
  assert_eq!(Ristretto::generator() * secret_key, public_key);
  let threshold_keys =
    musig::<Ristretto>(&musig_context(set), &Zeroizing::new(secret_key), &[public_key]).unwrap();
  assert_eq!(
    serai
      .as_of_latest_finalized_block()
      .await
      .unwrap()
      .validator_sets()
      .musig_key(set)
      .await
      .unwrap()
      .unwrap(),
    threshold_keys.group_key().to_bytes()
  );

  let sig = frost::tests::sign_without_caching(
    &mut OsRng,
    frost::tests::algorithm_machines(
      &mut OsRng,
      Schnorrkel::new(b"substrate"),
      &HashMap::from([(threshold_keys.params().i(), threshold_keys.into())]),
    ),
    &set_keys_message(&set, &key_pair),
  );

  // Set the key pair
  let block = publish_tx(
    serai,
    &SeraiValidatorSets::set_keys(set.network, key_pair.clone(), Signature(sig.to_bytes())),
  )
  .await;

  assert_eq!(
    serai.as_of(block).validator_sets().key_gen_events().await.unwrap(),
    vec![ValidatorSetsEvent::KeyGen { set, key_pair: key_pair.clone() }]
  );
  assert_eq!(serai.as_of(block).validator_sets().keys(set).await.unwrap(), Some(key_pair));

  block
}
