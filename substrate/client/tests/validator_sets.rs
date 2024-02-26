use rand_core::{RngCore, OsRng};

use sp_core::{sr25519::Public, Pair};

use serai_client::{
  primitives::{NETWORKS, NetworkId, insecure_pair_from_name},
  validator_sets::{
    primitives::{Session, ValidatorSet, KeyPair},
    ValidatorSetsEvent,
  },
  Amount, Serai,
};

mod common;
use common::validator_sets::{set_keys, allocate_stake, deallocate_stake};

// TODO: get rid of this is constant and retrive the epoch numbers from sthe node directly
// since epochs doesn't always change at the exact intervals.
const EPOCH_INTERVAL: u64 = 300;

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
        .as_of(serai.finalized_block_by_number(0).await.unwrap().unwrap().hash())
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
      let vs_serai = serai.as_of_latest_finalized_block().await.unwrap();
      let vs_serai = vs_serai.validator_sets();
      let participants = vs_serai.participants(set.network).await
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect::<Vec<_>>();
      let participants_ref: &[_] = participants.as_ref();
      assert_eq!(participants_ref, [public].as_ref());
    }

    let block = set_keys(&serai, set, key_pair.clone()).await;

    // While the set_keys function should handle this, it's beneficial to
    // independently test it
    let serai = serai.as_of(block);
    let serai = serai.validator_sets();
    assert_eq!(
      serai.key_gen_events().await.unwrap(),
      vec![ValidatorSetsEvent::KeyGen { set, key_pair: key_pair.clone() }]
    );
    assert_eq!(serai.keys(set).await.unwrap(), Some(key_pair));
  })
);

#[tokio::test]
async fn validator_set_rotation() {
  use dockertest::{
    PullPolicy, StartPolicy, LogOptions, LogAction, LogPolicy, LogSource, Image,
    TestBodySpecification, DockerTest,
  };
  use std::collections::HashMap;

  serai_docker_tests::build("serai-fast-epoch".to_string());

  let handle = |name| format!("serai_client-serai_node-{name}");
  let composition = |name| {
    TestBodySpecification::with_image(
      Image::with_repository("serai-dev-serai-fast-epoch").pull_policy(PullPolicy::Never),
    )
    .replace_cmd(vec![
      "serai-node".to_string(),
      "--unsafe-rpc-external".to_string(),
      "--rpc-cors".to_string(),
      "all".to_string(),
      "--chain".to_string(),
      "local".to_string(),
      format!("--{name}"),
    ])
    .replace_env(HashMap::from([("RUST_LOG=runtime".to_string(), "debug".to_string())]))
    .set_publish_all_ports(true)
    .set_handle(handle(name))
    .set_start_policy(StartPolicy::Strict)
    .set_log_options(Some(LogOptions {
      action: LogAction::Forward,
      policy: LogPolicy::Always,
      source: LogSource::Both,
    }))
  };

  let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
  test.provide_container(composition("alice"));
  test.provide_container(composition("bob"));
  test.provide_container(composition("charlie"));
  test.provide_container(composition("dave"));
  test.provide_container(composition("eve"));
  test
    .run_async(|ops| async move {
      // Sleep until the Substrate RPC starts
      let alice = handle("alice");
      let alice_rpc = ops.handle(&alice).host_port(9944).unwrap();
      let alice_rpc = format!("http://{}:{}", alice_rpc.0, alice_rpc.1);

      // Sleep for some time
      tokio::time::sleep(core::time::Duration::from_secs(20)).await;
      let serai = Serai::new(alice_rpc.clone()).await.unwrap();

      // Make sure the genesis is as expected
      assert_eq!(
        serai
          .as_of(serai.finalized_block_by_number(0).await.unwrap().unwrap().hash())
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

      // genesis accounts
      let pair1 = insecure_pair_from_name("Alice");
      let pair2 = insecure_pair_from_name("Bob");
      let pair3 = insecure_pair_from_name("Charlie");
      let pair4 = insecure_pair_from_name("Dave");
      let pair5 = insecure_pair_from_name("Eve");

      // amounts for single key share per network
      let key_shares = HashMap::from([
        (NetworkId::Serai, Amount(50_000 * 10_u64.pow(8))),
        (NetworkId::Bitcoin, Amount(1_000_000 * 10_u64.pow(8))),
        (NetworkId::Monero, Amount(100_000 * 10_u64.pow(8))),
        (NetworkId::Ethereum, Amount(1_000_000 * 10_u64.pow(8))),
      ]);

      // genesis participants per network
      let default_participants =
        vec![pair1.public(), pair2.public(), pair3.public(), pair4.public()];
      let mut participants = HashMap::from([
        (NetworkId::Serai, default_participants.clone()),
        (NetworkId::Bitcoin, default_participants.clone()),
        (NetworkId::Monero, default_participants.clone()),
        (NetworkId::Ethereum, default_participants),
      ]);

      // test the set rotation
      for (i, network) in NETWORKS.into_iter().enumerate() {
        let participants = participants.get_mut(&network).unwrap();

        // we start the chain with 4 default participants that has a single key share each
        participants.sort();
        verify_session_and_active_validators(&serai, network, 0, &participants).await;

        // add 1 participant & verify
        let hash =
          allocate_stake(&serai, network, key_shares[&network], &pair5, i.try_into().unwrap())
            .await;
        participants.push(pair5.public());
        participants.sort();
        verify_session_and_active_validators(
          &serai,
          network,
          get_active_session(&serai, network, hash).await,
          &participants,
        )
        .await;

        // remove 1 participant & verify
        let hash =
          deallocate_stake(&serai, network, key_shares[&network], &pair2, i.try_into().unwrap())
            .await;
        participants.swap_remove(participants.iter().position(|k| *k == pair2.public()).unwrap());
        let active_session = get_active_session(&serai, network, hash).await;
        participants.sort();
        verify_session_and_active_validators(&serai, network, active_session, &participants).await;

        // check pending deallocations
        let pending = serai
          .as_of_latest_finalized_block()
          .await
          .unwrap()
          .validator_sets()
          .pending_deallocations(
            network,
            pair2.public(),
            Session(u32::try_from(active_session + 1).unwrap()),
          )
          .await
          .unwrap();
        assert_eq!(pending, Some(key_shares[&network]));
      }
    })
    .await;
}

async fn verify_session_and_active_validators(
  serai: &Serai,
  network: NetworkId,
  session: u64,
  participants: &[Public],
) {
  // wait untill the epoch block finalized
  let epoch_block = (session * EPOCH_INTERVAL) + 1;
  while serai.finalized_block_by_number(epoch_block).await.unwrap().is_none() {
    // sleep 1 block
    tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
  }
  let serai_for_block =
    serai.as_of(serai.finalized_block_by_number(epoch_block).await.unwrap().unwrap().hash());

  // verify session
  let s = serai_for_block.validator_sets().session(network).await.unwrap().unwrap();
  assert_eq!(u64::from(s.0), session);

  // verify participants
  let mut validators =
    serai_for_block.validator_sets().active_network_validators(network).await.unwrap();
  validators.sort();
  assert_eq!(validators, participants);

  // make sure finalization continues as usual after the changes
  tokio::time::timeout(tokio::time::Duration::from_secs(60), async move {
    let mut finalized_block = serai.latest_finalized_block().await.unwrap().header.number;
    while finalized_block <= epoch_block + 2 {
      tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
      finalized_block = serai.latest_finalized_block().await.unwrap().header.number;
    }
  })
  .await
  .unwrap();

  // TODO: verify key shares as well?
}

async fn get_active_session(serai: &Serai, network: NetworkId, hash: [u8; 32]) -> u64 {
  let block_number = serai.block(hash).await.unwrap().unwrap().header.number;
  let epoch = block_number / EPOCH_INTERVAL;

  // changes should be active in the next session
  if network == NetworkId::Serai {
    // it takes 1 extra session for serai net to make the changes active.
    epoch + 2
  } else {
    epoch + 1
  }
}
