use std::collections::HashMap;

use rand_core::OsRng;

use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite, Ristretto,
};

use serai_primitives::NetworkId;

use dockertest::{
  PullPolicy, Image, LogAction, LogPolicy, LogSource, LogOptions, TestBodySpecification,
};

pub type MessageQueuePrivateKey = <Ristretto as Ciphersuite>::F;
pub fn instance(
) -> (MessageQueuePrivateKey, HashMap<NetworkId, MessageQueuePrivateKey>, TestBodySpecification) {
  serai_docker_tests::build("message-queue".to_string());

  let coord_key = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
  let priv_keys = HashMap::from([
    (NetworkId::Bitcoin, <Ristretto as Ciphersuite>::F::random(&mut OsRng)),
    (NetworkId::Ethereum, <Ristretto as Ciphersuite>::F::random(&mut OsRng)),
    (NetworkId::Monero, <Ristretto as Ciphersuite>::F::random(&mut OsRng)),
  ]);

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-message-queue").pull_policy(PullPolicy::Never),
  )
  .set_log_options(Some(LogOptions {
    action: LogAction::Forward,
    policy: LogPolicy::Always,
    source: LogSource::Both,
  }))
  .replace_env(
    [
      ("COORDINATOR_KEY".to_string(), hex::encode((Ristretto::generator() * coord_key).to_bytes())),
      (
        "BITCOIN_KEY".to_string(),
        hex::encode((Ristretto::generator() * priv_keys[&NetworkId::Bitcoin]).to_bytes()),
      ),
      (
        "ETHEREUM_KEY".to_string(),
        hex::encode((Ristretto::generator() * priv_keys[&NetworkId::Ethereum]).to_bytes()),
      ),
      (
        "MONERO_KEY".to_string(),
        hex::encode((Ristretto::generator() * priv_keys[&NetworkId::Monero]).to_bytes()),
      ),
      ("DB_PATH".to_string(), "./message-queue-db".to_string()),
      ("RUST_LOG".to_string(), "serai_message_queue=trace,".to_string()),
    ]
    .into(),
  )
  .set_publish_all_ports(true);

  (coord_key, priv_keys, composition)
}

#[test]
fn basic_functionality() {
  use zeroize::Zeroizing;

  use dockertest::DockerTest;

  use serai_message_queue::{Service, Metadata, client::MessageQueue};

  let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
  let (coord_key, priv_keys, composition) = instance();
  test.provide_container(composition);
  test.run(|ops| async move {
    tokio::time::timeout(core::time::Duration::from_secs(60), async move {
      // Sleep for a second for the message-queue to boot
      // It isn't an error to start immediately, it just silences an error
      tokio::time::sleep(core::time::Duration::from_secs(1)).await;

      let rpc = ops.handle("serai-dev-message-queue").host_port(2287).unwrap();
      let rpc = rpc.0.to_string() + ":" + &rpc.1.to_string();

      // Queue some messages
      let mut coordinator =
        MessageQueue::new(Service::Coordinator, rpc.clone(), Zeroizing::new(coord_key));
      coordinator
        .queue(
          Metadata {
            from: Service::Coordinator,
            to: Service::Processor(NetworkId::Bitcoin),
            intent: b"intent".to_vec(),
          },
          b"Hello, World!".to_vec(),
        )
        .await;

      // Queue this twice, which message-queue should de-duplicate
      for _ in 0 .. 2 {
        coordinator
          .queue(
            Metadata {
              from: Service::Coordinator,
              to: Service::Processor(NetworkId::Bitcoin),
              intent: b"intent 2".to_vec(),
            },
            b"Hello, World, again!".to_vec(),
          )
          .await;
      }

      // Successfully get it
      let mut bitcoin = MessageQueue::new(
        Service::Processor(NetworkId::Bitcoin),
        rpc.clone(),
        Zeroizing::new(priv_keys[&NetworkId::Bitcoin]),
      );
      let msg = bitcoin.next(Service::Coordinator).await;
      assert_eq!(msg.from, Service::Coordinator);
      assert_eq!(msg.id, 0);
      assert_eq!(&msg.msg, b"Hello, World!");

      // If we don't ack it, it should continue to be returned
      assert_eq!(msg, bitcoin.next(Service::Coordinator).await);

      // Acknowledging it should yield the next message
      bitcoin.ack(Service::Coordinator, 0).await;

      let next_msg = bitcoin.next(Service::Coordinator).await;
      assert!(msg != next_msg);
      assert_eq!(next_msg.from, Service::Coordinator);
      assert_eq!(next_msg.id, 1);
      assert_eq!(&next_msg.msg, b"Hello, World, again!");
      bitcoin.ack(Service::Coordinator, 1).await;

      // No further messages should be available
      tokio::time::timeout(core::time::Duration::from_secs(10), bitcoin.next(Service::Coordinator))
        .await
        .unwrap_err();

      // Queueing to a distinct processor should work, with a unique ID
      coordinator
        .queue(
          Metadata {
            from: Service::Coordinator,
            to: Service::Processor(NetworkId::Monero),
            // Intents should be per-from-to, making this valid
            intent: b"intent".to_vec(),
          },
          b"Hello, World!".to_vec(),
        )
        .await;

      let mut monero = MessageQueue::new(
        Service::Processor(NetworkId::Monero),
        rpc,
        Zeroizing::new(priv_keys[&NetworkId::Monero]),
      );
      assert_eq!(monero.next(Service::Coordinator).await.id, 0);
      monero.ack(Service::Coordinator, 0).await;
      tokio::time::timeout(core::time::Duration::from_secs(10), monero.next(Service::Coordinator))
        .await
        .unwrap_err();
    })
    .await
    .unwrap();
  });
}
