use rand_core::{RngCore, OsRng};

use sp_core::{sr25519::Public, Pair};
use subxt::{config::extrinsic_params::BaseExtrinsicParamsBuilder};

use serai_client::{
  primitives::{BITCOIN_NET_ID, BITCOIN_NET, insecure_pair_from_name},
  validator_sets::{
    primitives::{Session, ValidatorSet},
    ValidatorSetsEvent,
  },
  PairSigner, Serai,
};

mod runner;
use runner::{URL, publish_tx};

serai_test!(
  async fn vote_keys() {
    let network = BITCOIN_NET_ID;
    let set = ValidatorSet { session: Session(0), network };

    // Neither of these keys are validated
    // The external key is infeasible to validate on-chain, the Ristretto key is feasible
    // TODO: Should the Ristretto key be validated?
    let mut ristretto_key = [0; 32];
    OsRng.fill_bytes(&mut ristretto_key);
    let mut external_key = vec![0; 33];
    OsRng.fill_bytes(&mut external_key);
    let key_pair = (Public(ristretto_key), external_key.try_into().unwrap());

    let pair = insecure_pair_from_name("Alice");
    let public = pair.public();

    let serai = Serai::new(URL).await.unwrap();

    // Make sure the genesis is as expected
    let set_data = serai.get_validator_set(set).await.unwrap().unwrap();
    assert_eq!(set_data.network, *BITCOIN_NET);
    let participants_ref: &[_] = set_data.participants.as_ref();
    assert_eq!(participants_ref, [(public, set_data.bond)].as_ref());

    // Vote in a key pair
    let block = publish_tx(
      &serai,
      &serai
        .sign(
          &PairSigner::new(pair),
          &Serai::vote(network, key_pair.clone()),
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
  }
);
