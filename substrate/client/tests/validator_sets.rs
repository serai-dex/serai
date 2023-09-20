use rand_core::{RngCore, OsRng};

use sp_core::{sr25519::Public, Pair};

use serai_client::{
  primitives::{NETWORKS, NetworkId, insecure_pair_from_name},
  validator_sets::{
    primitives::{Session, ValidatorSet, musig_key},
    ValidatorSetsEvent,
  },
  Serai,
};

mod common;
use common::{serai, validator_sets::set_validator_set_keys};

serai_test!(
  async fn set_validator_set_keys_test() {
    let network = NetworkId::Bitcoin;
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
    assert_eq!(
      serai
        .get_new_set_events(serai.get_block_by_number(0).await.unwrap().unwrap().hash())
        .await
        .unwrap(),
      [NetworkId::Bitcoin, NetworkId::Ethereum, NetworkId::Monero, NetworkId::Serai]
        .iter()
        .copied()
        .map(|network| ValidatorSetsEvent::NewSet {
          set: ValidatorSet { session: Session(0), network }
        })
        .collect::<Vec<_>>(),
    );

    let set_data = serai.get_validator_set(set).await.unwrap().unwrap();
    assert_eq!(set_data.network, NETWORKS[&NetworkId::Bitcoin]);
    let participants_ref: &[_] = set_data.participants.as_ref();
    assert_eq!(participants_ref, [(public, set_data.bond)].as_ref());
    assert_eq!(
      serai.get_validator_set_musig_key(set).await.unwrap().unwrap(),
      musig_key(set, &[public]).0
    );

    let block = set_validator_set_keys(set, key_pair.clone()).await;

    // While the set_validator_set_keys function should handle this, it's beneficial to
    // independently test it
    assert_eq!(
      serai.get_key_gen_events(block).await.unwrap(),
      vec![ValidatorSetsEvent::KeyGen { set, key_pair: key_pair.clone() }]
    );
    assert_eq!(serai.get_keys(set).await.unwrap(), Some(key_pair));
  }
);
