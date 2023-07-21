use rand_core::{RngCore, OsRng};

use ciphersuite::{group::ff::PrimeField, Ciphersuite, Ristretto};

use dockertest::{
  PullPolicy, Image, LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, Composition,
};

pub fn bitcoin_instance() -> Composition {
  serai_docker_tests::build("bitcoin".to_string());

  Composition::with_image(
    Image::with_repository("serai-dev-bitcoin").pull_policy(PullPolicy::Never),
  )
  .with_log_options(Some(LogOptions {
    action: LogAction::Forward,
    policy: LogPolicy::Always,
    source: LogSource::Both,
  }))
  .with_cmd(vec![
    "bitcoind".to_string(),
    "-txindex".to_string(),
    "-regtest".to_string(),
    "-rpcuser=serai".to_string(),
    "-rpcpassword=seraidex".to_string(),
    "-rpcbind=0.0.0.0".to_string(),
    "-rpcallowip=0.0.0.0/0".to_string(),
    "-rpcport=8332".to_string(),
  ])
  .with_start_policy(StartPolicy::Strict)
}

pub fn instance(message_queue_key: <Ristretto as Ciphersuite>::F) -> Composition {
  serai_docker_tests::build("processor".to_string());

  let mut entropy = [0; 32];
  OsRng.fill_bytes(&mut entropy);

  Composition::with_image(
    Image::with_repository("serai-dev-processor").pull_policy(PullPolicy::Never),
  )
  .with_log_options(Some(LogOptions {
    action: LogAction::Forward,
    policy: LogPolicy::Always,
    source: LogSource::Both,
  }))
  .with_env(
    [
      ("MESSAGE_QUEUE_KEY".to_string(), hex::encode(message_queue_key.to_repr())),
      ("ENTROPY".to_string(), hex::encode(entropy)),
      ("NETWORK".to_string(), "bitcoin".to_string()),
      ("NETWORK_RPC_LOGIN".to_string(), "serai:seraidex".to_string()),
      ("NETWORK_RPC_PORT".to_string(), "8332".to_string()),
      ("DB_PATH".to_string(), "./processor-db".to_string()),
    ]
    .into(),
  )
  .with_start_policy(StartPolicy::Strict)
}

#[test]
fn basic_functionality() {
  use std::env;

  use serai_primitives::NetworkId;
  use serai_validator_sets_primitives::{Session, ValidatorSet};

  use serai_message_queue::{Service, Metadata, client::MessageQueue};

  use dockertest::DockerTest;

  let bitcoin_composition = bitcoin_instance();

  let (coord_key, message_queue_keys, message_queue_composition) =
    serai_message_queue_tests::instance();
  let message_queue_composition = message_queue_composition.with_start_policy(StartPolicy::Strict);

  let mut processor_composition = instance(message_queue_keys[&NetworkId::Bitcoin]);
  processor_composition.inject_container_name(bitcoin_composition.handle(), "NETWORK_RPC_HOSTNAME");
  processor_composition
    .inject_container_name(message_queue_composition.handle(), "MESSAGE_QUEUE_RPC");

  let mut test = DockerTest::new();
  test.add_composition(bitcoin_composition);
  test.add_composition(message_queue_composition);
  test.add_composition(processor_composition);

  test.run(|ops| async move {
    // Sleep for 10 seconds to be polite and let things boot
    tokio::time::sleep(core::time::Duration::from_secs(10)).await;

    // Connect to the Message Queue as the coordinator
    let rpc = ops.handle("serai-dev-message-queue").host_port(2287).unwrap();
    // TODO: MessageQueue::new
    env::set_var(
      "MESSAGE_QUEUE_RPC",
      "http://".to_string() + &rpc.0.to_string() + ":" + &rpc.1.to_string(),
    );
    env::set_var("MESSAGE_QUEUE_KEY", hex::encode(coord_key.to_repr()));
    let coordinator = MessageQueue::from_env(Service::Coordinator);

    // Order a key gen
    let id = messages::key_gen::KeyGenId {
      set: ValidatorSet { session: Session(0), network: NetworkId::Bitcoin },
      attempt: 0,
    };

    coordinator
      .queue(
        Metadata {
          from: Service::Coordinator,
          to: Service::Processor(NetworkId::Bitcoin),
          intent: b"key_gen_0".to_vec(),
        },
        serde_json::to_string(&messages::CoordinatorMessage::KeyGen(
          messages::key_gen::CoordinatorMessage::GenerateKey {
            id,
            params: dkg::ThresholdParams::new(3, 4, dkg::Participant::new(1).unwrap()).unwrap(),
          },
        ))
        .unwrap()
        .into_bytes(),
      )
      .await;

    // Read the created commitments
    let msg = coordinator.next(0).await;
    assert_eq!(msg.from, Service::Processor(NetworkId::Bitcoin));
    assert_eq!(msg.id, 0);
    let msg: messages::ProcessorMessage = serde_json::from_slice(&msg.msg).unwrap();
    match msg {
      messages::ProcessorMessage::KeyGen(messages::key_gen::ProcessorMessage::Commitments {
        id: this_id,
        commitments: _,
      }) => {
        assert_eq!(this_id, id);
      }
      _ => panic!("processor didn't return Commitments in response to GenerateKey"),
    }
    coordinator.ack(0).await;
  });
}
