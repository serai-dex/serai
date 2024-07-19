use rand_core::{RngCore, OsRng};

use sp_core::{
  sr25519::{Public, Pair},
  Pair as PairTrait,
};

use serai_client::{
  primitives::{NETWORKS, NetworkId, BlockHash, insecure_pair_from_name},
  validator_sets::{
    primitives::{Session, ValidatorSet, KeyPair},
    ValidatorSetsEvent,
  },
  in_instructions::{
    primitives::{Batch, SignedBatch, batch_message},
    SeraiInInstructions,
  },
  Amount, Serai,
};

mod common;
use common::{
  tx::publish_tx,
  validator_sets::{allocate_stake, deallocate_stake, set_keys},
};

fn get_random_key_pair() -> KeyPair {
  let mut ristretto_key = [0; 32];
  OsRng.fill_bytes(&mut ristretto_key);
  let mut external_key = vec![0; 33];
  OsRng.fill_bytes(&mut external_key);
  KeyPair(Public(ristretto_key), external_key.try_into().unwrap())
}

async fn get_ordered_keys(serai: &Serai, network: NetworkId, accounts: &[Pair]) -> Vec<Pair> {
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

serai_test!(
  set_keys_test: (|serai: Serai| async move {
    let network = NetworkId::Bitcoin;
    let set = ValidatorSet { session: Session(0), network };

    let pair = insecure_pair_from_name("Alice");
    let public = pair.public();

    // Neither of these keys are validated
    // The external key is infeasible to validate on-chain, the Ristretto key is feasible
    // TODO: Should the Ristretto key be validated?
    let key_pair = get_random_key_pair();

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

    let block = set_keys(&serai, set, key_pair.clone(), &[pair]).await;

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
    .replace_env(HashMap::from([
      ("RUST_LOG".to_string(), "runtime=debug".to_string()),
      ("KEY".to_string(), " ".to_string()),
    ]))
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
      let accounts = vec![
        insecure_pair_from_name("Alice"),
        insecure_pair_from_name("Bob"),
        insecure_pair_from_name("Charlie"),
        insecure_pair_from_name("Dave"),
        insecure_pair_from_name("Eve"),
      ];

      // amounts for single key share per network
      let key_shares = HashMap::from([
        (NetworkId::Serai, Amount(50_000 * 10_u64.pow(8))),
        (NetworkId::Bitcoin, Amount(1_000_000 * 10_u64.pow(8))),
        (NetworkId::Monero, Amount(100_000 * 10_u64.pow(8))),
        (NetworkId::Ethereum, Amount(1_000_000 * 10_u64.pow(8))),
      ]);

      // genesis participants per network
      #[allow(clippy::redundant_closure_for_method_calls)]
      let default_participants =
        accounts[.. 4].to_vec().iter().map(|pair| pair.public()).collect::<Vec<_>>();
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
        verify_session_and_active_validators(&serai, network, 0, participants).await;

        // add 1 participant
        let last_participant = accounts[4].clone();
        let hash = allocate_stake(
          &serai,
          network,
          key_shares[&network],
          &last_participant,
          i.try_into().unwrap(),
        )
        .await;
        participants.push(last_participant.public());
        // the session at which set changes becomes active
        let activation_session = get_session_at_which_changes_activate(&serai, network, hash).await;

        // set the keys if it is an external set
        if network != NetworkId::Serai {
          let set = ValidatorSet { session: Session(0), network };
          let key_pair = get_random_key_pair();
          let pairs = get_ordered_keys(&serai, network, &accounts).await;
          set_keys(&serai, set, key_pair, &pairs).await;
        }

        // verify
        participants.sort();
        verify_session_and_active_validators(&serai, network, activation_session, participants)
          .await;

        // remove 1 participant
        let participant_to_remove = accounts[1].clone();
        let hash = deallocate_stake(
          &serai,
          network,
          key_shares[&network],
          &participant_to_remove,
          i.try_into().unwrap(),
        )
        .await;
        participants.swap_remove(
          participants.iter().position(|k| *k == participant_to_remove.public()).unwrap(),
        );
        let activation_session = get_session_at_which_changes_activate(&serai, network, hash).await;

        if network != NetworkId::Serai {
          // set the keys if it is an external set
          let set = ValidatorSet { session: Session(1), network };

          // we need the whole substrate key pair to sign the batch
          let (substrate_pair, key_pair) = {
            let pair = insecure_pair_from_name("session-1-key-pair");
            let public = pair.public();

            let mut external_key = vec![0; 33];
            OsRng.fill_bytes(&mut external_key);

            (pair, KeyPair(public, external_key.try_into().unwrap()))
          };
          let pairs = get_ordered_keys(&serai, network, &accounts).await;
          set_keys(&serai, set, key_pair, &pairs).await;

          // provide a batch to complete the handover and retire the previous set
          let mut block_hash = BlockHash([0; 32]);
          OsRng.fill_bytes(&mut block_hash.0);
          let batch = Batch { network, id: 0, block: block_hash, instructions: vec![] };
          publish_tx(
            &serai,
            &SeraiInInstructions::execute_batch(SignedBatch {
              batch: batch.clone(),
              signature: substrate_pair.sign(&batch_message(&batch)),
            }),
          )
          .await;
        }

        // verify
        participants.sort();
        verify_session_and_active_validators(&serai, network, activation_session, participants)
          .await;

        // check pending deallocations
        let pending = serai
          .as_of_latest_finalized_block()
          .await
          .unwrap()
          .validator_sets()
          .pending_deallocations(
            network,
            participant_to_remove.public(),
            Session(activation_session + 1),
          )
          .await
          .unwrap();
        assert_eq!(pending, Some(key_shares[&network]));
      }
    })
    .await;
}

async fn session_for_block(serai: &Serai, block: [u8; 32], network: NetworkId) -> u32 {
  serai.as_of(block).validator_sets().session(network).await.unwrap().unwrap().0
}

async fn verify_session_and_active_validators(
  serai: &Serai,
  network: NetworkId,
  session: u32,
  participants: &[Public],
) {
  // wait until the active session. This wait should be max 30 secs since the epoch time.
  let block = tokio::time::timeout(core::time::Duration::from_secs(2 * 60), async move {
    loop {
      let mut block = serai.latest_finalized_block_hash().await.unwrap();
      if session_for_block(serai, block, network).await < session {
        // Sleep a block
        tokio::time::sleep(core::time::Duration::from_secs(6)).await;
        continue;
      }
      while session_for_block(serai, block, network).await > session {
        block = serai.block(block).await.unwrap().unwrap().header.parent_hash.0;
      }
      assert_eq!(session_for_block(serai, block, network).await, session);
      break block;
    }
  })
  .await
  .unwrap();
  let serai_for_block = serai.as_of(block);

  // verify session
  let s = serai_for_block.validator_sets().session(network).await.unwrap().unwrap();
  assert_eq!(s.0, session);

  // verify participants
  let mut validators =
    serai_for_block.validator_sets().active_network_validators(network).await.unwrap();
  validators.sort();
  assert_eq!(validators, participants);

  // make sure finalization continues as usual after the changes
  let current_finalized_block = serai.latest_finalized_block().await.unwrap().header.number;
  tokio::time::timeout(core::time::Duration::from_secs(60), async move {
    let mut finalized_block = serai.latest_finalized_block().await.unwrap().header.number;
    while finalized_block <= current_finalized_block + 2 {
      tokio::time::sleep(core::time::Duration::from_secs(6)).await;
      finalized_block = serai.latest_finalized_block().await.unwrap().header.number;
    }
  })
  .await
  .unwrap();

  // TODO: verify key shares as well?
}

async fn get_session_at_which_changes_activate(
  serai: &Serai,
  network: NetworkId,
  hash: [u8; 32],
) -> u32 {
  let session = session_for_block(serai, hash, network).await;

  // changes should be active in the next session
  if network == NetworkId::Serai {
    // it takes 1 extra session for serai net to make the changes active.
    session + 2
  } else {
    session + 1
  }
}
