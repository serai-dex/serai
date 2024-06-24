use std::collections::HashMap;

use serai_abi::primitives::NetworkId;
use zeroize::Zeroizing;
use rand_core::OsRng;

use sp_core::{
  sr25519::{Pair, Signature},
  Pair as PairTrait,
};

use ciphersuite::{Ciphersuite, Ristretto};
use frost::dkg::musig::musig;
use schnorrkel::Schnorrkel;

use serai_client::{
  validator_sets::{
    primitives::{ValidatorSet, KeyPair, musig_context, set_keys_message},
    ValidatorSetsEvent,
  },
  Amount, Serai, SeraiValidatorSets,
};

use crate::common::tx::publish_tx;

#[allow(dead_code)]
pub async fn set_keys(
  serai: &Serai,
  set: ValidatorSet,
  key_pair: KeyPair,
  pairs: &[Pair],
) -> [u8; 32] {
  let mut pub_keys = vec![];
  for pair in pairs {
    let public_key =
      <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut pair.public().0.as_ref()).unwrap();
    pub_keys.push(public_key);
  }

  let mut threshold_keys = vec![];
  for i in 0 .. pairs.len() {
    let secret_key = <Ristretto as Ciphersuite>::read_F::<&[u8]>(
      &mut pairs[i].as_ref().secret.to_bytes()[.. 32].as_ref(),
    )
    .unwrap();
    assert_eq!(Ristretto::generator() * secret_key, pub_keys[i]);

    threshold_keys.push(
      musig::<Ristretto>(&musig_context(set), &Zeroizing::new(secret_key), &pub_keys).unwrap(),
    );
  }

  let mut musig_keys = HashMap::new();
  for tk in threshold_keys {
    musig_keys.insert(tk.params().i(), tk.into());
  }

  let sig = frost::tests::sign_without_caching(
    &mut OsRng,
    frost::tests::algorithm_machines(&mut OsRng, &Schnorrkel::new(b"substrate"), &musig_keys),
    &set_keys_message(&set, &[], &key_pair),
  );

  // Set the key pair
  let block = publish_tx(
    serai,
    &SeraiValidatorSets::set_keys(
      set.network,
      vec![].try_into().unwrap(),
      key_pair.clone(),
      Signature(sig.to_bytes()),
    ),
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
