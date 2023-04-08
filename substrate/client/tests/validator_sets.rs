use rand_core::{RngCore, OsRng};

use sp_core::{sr25519::Public, Pair};

use serai_client::{
  primitives::{BITCOIN_NET_ID, BITCOIN_NET, insecure_pair_from_name},
  validator_sets::{
    primitives::{Session, ValidatorSet},
    ValidatorSetsEvent,
  },
  Serai,
};

mod common;
use common::{serai, validator_sets::vote_in_keys};

serai_test!(
  async fn vote_keys() {
    let network = BITCOIN_NET_ID;
    let set = ValidatorSet { session: Session(0), network };

    let public = insecure_pair_from_name("Alice").public();

    // Neither of these keys are validated
    // The external key is infeasible to validate on-chain, the Ristretto key is feasible
    // TODO: Should the Ristretto key be validated?
    let mut ristretto_key = [0; 32];
    OsRng.fill_bytes(&mut ristretto_key);
    let mut external_key = vec![0; 33];
    OsRng.fill_bytes(&mut external_key);
    let key_pair = (Public(ristretto_key), external_key.try_into().unwrap());

    let serai = serai().await;

    // Make sure the genesis is as expected
    let set_data = serai.get_validator_set(set).await.unwrap().unwrap();
    assert_eq!(set_data.network, *BITCOIN_NET);
    let participants_ref: &[_] = set_data.participants.as_ref();
    assert_eq!(participants_ref, [(public, set_data.bond)].as_ref());

    let block = vote_in_keys(set, key_pair.clone()).await;

    // While the vote_in_keys function should handle this, it's beneficial to independently test it
    assert_eq!(
      serai.get_vote_events(block).await.unwrap(),
      vec![ValidatorSetsEvent::Vote { voter: public, set, key_pair: key_pair.clone(), votes: 1 }]
    );
    assert_eq!(
      serai.get_key_gen_events(block).await.unwrap(),
      vec![ValidatorSetsEvent::KeyGen { set, key_pair: key_pair.clone() }]
    );
    assert_eq!(serai.get_keys(set).await.unwrap(), Some(key_pair));
  }
);
