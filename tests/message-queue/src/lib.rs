#[cfg(test)]
mod tests {
  use std::{
    sync::{Mutex, OnceLock},
    collections::HashMap,
    env,
  };

  use rand_core::OsRng;

  use ciphersuite::{
    group::{
      ff::{Field, PrimeField},
      GroupEncoding,
    },
    Ciphersuite, Ristretto,
  };

  use serai_primitives::NetworkId;
  use serai_message_queue::{Service, Metadata, client::MessageQueue};

  use dockertest::{
    PullPolicy, Image, LogAction, LogPolicy, LogSource, LogOptions, Composition, DockerTest,
  };

  static BUILT: OnceLock<Mutex<bool>> = OnceLock::new();
  fn build() {
    let built = BUILT.get_or_init(|| Mutex::new(false));
    // Only one call to build will acquire this lock
    let mut built_lock = built.lock().unwrap();
    if *built_lock {
      // If it was built, return
      return;
    }

    // Else, hold the lock while we build
    let mut path = env::current_exe().unwrap();
    path.pop();
    assert!(path.as_path().ends_with("deps"));
    path.pop();
    assert!(path.as_path().ends_with("debug"));
    path.pop();
    assert!(path.as_path().ends_with("target"));
    path.pop();
    path.push("deploy");

    println!("Building message-queue...");

    assert!(std::process::Command::new("docker")
      .current_dir(path)
      .arg("compose")
      .arg("build")
      .arg("message-queue")
      .spawn()
      .unwrap()
      .wait()
      .unwrap()
      .success());

    println!("Built!");

    // Set built
    *built_lock = true;
  }

  type PrivateKey = <Ristretto as Ciphersuite>::F;
  fn instance() -> (PrivateKey, HashMap<NetworkId, PrivateKey>, Composition) {
    build();

    let coord_key = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
    let priv_keys = HashMap::from([
      (NetworkId::Bitcoin, <Ristretto as Ciphersuite>::F::random(&mut OsRng)),
      (NetworkId::Ethereum, <Ristretto as Ciphersuite>::F::random(&mut OsRng)),
      (NetworkId::Monero, <Ristretto as Ciphersuite>::F::random(&mut OsRng)),
    ]);

    let mut composition = Composition::with_image(
      Image::with_repository("serai-dev-message-queue").pull_policy(PullPolicy::Never),
    )
    .with_log_options(Some(LogOptions {
      action: LogAction::Forward,
      policy: LogPolicy::Always,
      source: LogSource::Both,
    }))
    .with_env(
      [
        (
          "COORDINATOR_KEY".to_string(),
          hex::encode((Ristretto::generator() * coord_key).to_bytes()),
        ),
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
      ]
      .into(),
    );
    composition.publish_all_ports();

    (coord_key, priv_keys, composition)
  }

  #[test]
  fn basic_functionality() {
    let mut test = DockerTest::new();
    let (coord_key, priv_keys, composition) = instance();
    test.add_composition(composition);
    test.run(|ops| async move {
      // Sleep for a second for the message-queue to boot
      // It isn't an error to start immediately, it just silences an error
      tokio::time::sleep(core::time::Duration::from_secs(1)).await;

      let rpc = ops.handle("serai-dev-message-queue").host_port(2287).unwrap();
      // TODO: MessageQueue directly read from env to remove this boilerplate from all binaries,
      // yet it's now annoying as hell to parameterize. Split into new/from_env?
      env::set_var(
        "MESSAGE_QUEUE_RPC",
        "http://".to_string() + &rpc.0.to_string() + ":" + &rpc.1.to_string(),
      );
      env::set_var("MESSAGE_QUEUE_KEY", hex::encode(coord_key.to_repr()));

      // Queue some messagse
      let coordinator = MessageQueue::new(Service::Coordinator);
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

      // Successfully get it
      env::set_var("MESSAGE_QUEUE_KEY", hex::encode(priv_keys[&NetworkId::Bitcoin].to_repr()));
      let bitcoin = MessageQueue::new(Service::Processor(NetworkId::Bitcoin));
      let msg = bitcoin.next(0).await;
      assert_eq!(msg.from, Service::Coordinator);
      assert_eq!(msg.id, 0);
      assert_eq!(&msg.msg, b"Hello, World!");

      // If we don't ack it, it should continue to be returned
      assert_eq!(msg, bitcoin.next(0).await);

      // Acknowledging it should yield the next message
      bitcoin.ack(0).await;

      let next_msg = bitcoin.next(1).await;
      assert!(msg != next_msg);
      assert_eq!(next_msg.from, Service::Coordinator);
      assert_eq!(next_msg.id, 1);
      assert_eq!(&next_msg.msg, b"Hello, World, again!");
    });
  }
}
