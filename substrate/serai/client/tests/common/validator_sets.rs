use sp_core::Pair;

use serai_client::{
  subxt::config::extrinsic_params::BaseExtrinsicParamsBuilder,
  primitives::insecure_pair_from_name,
  validator_sets::{
    primitives::{ValidatorSet, KeyPair},
    ValidatorSetsEvent,
  },
  PairSigner, Serai,
};

use crate::common::{serai, tx::publish_tx};

#[allow(dead_code)]
pub async fn vote_in_key(set: ValidatorSet, key_pair: KeyPair) -> [u8; 32] {
  let pair = insecure_pair_from_name("Alice");
  let public = pair.public();

  let serai = serai().await;

  // Vote in a key pair
  let block = publish_tx(
    &serai
      .sign(
        &PairSigner::new(pair),
        &Serai::vote(set.network, key_pair.clone()),
        0,
        BaseExtrinsicParamsBuilder::new(),
      )
      .unwrap(),
  )
  .await;

  assert_eq!(
    serai.get_vote_events(block).await.unwrap(),
    vec![ValidatorSetsEvent::Vote { voter: public, set, key_pair: key_pair.clone(), votes: 1 }]
  );
  assert_eq!(
    serai.get_key_gen_events(block).await.unwrap(),
    vec![ValidatorSetsEvent::KeyGen { set, key_pair: key_pair.clone() }]
  );
  assert_eq!(serai.get_keys(set).await.unwrap(), Some(key_pair));

  block
}
