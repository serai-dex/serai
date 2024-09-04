use serai_abi::primitives::NetworkId;

use sp_core::{sr25519::Pair, Pair as PairTrait};

use serai_client::{
  validator_sets::{
    primitives::{ValidatorSet, KeyPair, set_keys_message},
    ValidatorSetsEvent,
  },
  Amount, Serai, SeraiValidatorSets,
};

use crate::common::tx::{publish_tx, get_musig_of_pairs};

#[allow(dead_code)]
pub async fn set_keys(
  serai: &Serai,
  set: ValidatorSet,
  key_pair: KeyPair,
  pairs: &[Pair],
) -> [u8; 32] {
  let sig = get_musig_of_pairs(pairs, set, &set_keys_message(&set, &[], &key_pair));

  // Set the key pair
  let block = publish_tx(
    serai,
    &SeraiValidatorSets::set_keys(set.network, vec![].try_into().unwrap(), key_pair.clone(), sig),
  )
  .await;

  assert_eq!(
    serai.as_of(block).validator_sets().key_gen_events().await.unwrap(),
    vec![ValidatorSetsEvent::KeyGen { set, key_pair: key_pair.clone() }]
  );
  assert_eq!(serai.as_of(block).validator_sets().keys(set).await.unwrap(), Some(key_pair));

  block
}

#[allow(dead_code)]
pub async fn get_ordered_keys(serai: &Serai, network: NetworkId, accounts: &[Pair]) -> Vec<Pair> {
  // retrieve the current session validators so that we know the order of the keys
  // that is necessary for the correct musig signature.
  let validators = serai
    .as_of_latest_finalized_block()
    .await
    .unwrap()
    .validator_sets()
    .active_network_validators(network)
    .await
    .unwrap();

  // collect the pairs of the validators
  let mut pairs = vec![];
  for v in validators {
    let p = accounts.iter().find(|pair| pair.public() == v).unwrap().clone();
    pairs.push(p);
  }

  pairs
}

#[allow(dead_code)]
pub async fn allocate_stake(
  serai: &Serai,
  network: NetworkId,
  amount: Amount,
  pair: &Pair,
  nonce: u32,
) -> [u8; 32] {
  // get the call
  let tx = serai.sign(pair, SeraiValidatorSets::allocate(network, amount), nonce, 0);
  publish_tx(serai, &tx).await
}

#[allow(dead_code)]
pub async fn deallocate_stake(
  serai: &Serai,
  network: NetworkId,
  amount: Amount,
  pair: &Pair,
  nonce: u32,
) -> [u8; 32] {
  // get the call
  let tx = serai.sign(pair, SeraiValidatorSets::deallocate(network, amount), nonce, 0);
  publish_tx(serai, &tx).await
}
