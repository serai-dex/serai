use rand_core::{RngCore, OsRng};

use sp_core::{sr25519::Public, Pair};

use serai_client::{
  primitives::{NETWORKS, NetworkId, insecure_pair_from_name},
  validator_sets::{
    primitives::{Session, ValidatorSet, KeyPair, musig_key},
    ValidatorSetsEvent,
  },
  Serai,
};

mod common;
use common::validator_sets::set_keys;

serai_test!(
  set_keys_test: (|serai: Serai| async move {
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
    let key_pair = KeyPair(Public(ristretto_key), external_key.try_into().unwrap());

    // Make sure the genesis is as expected
    assert_eq!(
      serai
        .as_of(serai.block_by_number(0).await.unwrap().unwrap().hash())
        .validator_sets()
        .new_set_events()
        .await
        .unwrap(),
      NETWORKS
        .iter()
        .copied()
        .map(|network| ValidatorSetsEvent::NewSet {
          set: ValidatorSet { session: Session(0), network }
        })
        .collect::<Vec<_>>(),
    );

    {
      let vs_serai = serai.with_current_latest_block().await.unwrap().validator_sets();
      let participants = vs_serai.participants(set.network).await
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect::<Vec<_>>();
      let participants_ref: &[_] = participants.as_ref();
      assert_eq!(participants_ref, [public].as_ref());
      assert_eq!(vs_serai.musig_key(set).await.unwrap().unwrap(), musig_key(set, &[public]).0);
    }

    let block = set_keys(&serai, set, key_pair.clone()).await;

    // While the set_keys function should handle this, it's beneficial to
    // independently test it
    let serai = serai.as_of(block).validator_sets();
    assert_eq!(
      serai.key_gen_events().await.unwrap(),
      vec![ValidatorSetsEvent::KeyGen { set, key_pair: key_pair.clone() }]
    );
    assert_eq!(serai.keys(set).await.unwrap(), Some(key_pair));
  })
);
