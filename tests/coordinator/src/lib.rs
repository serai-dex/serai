#![allow(clippy::needless_pass_by_ref_mut)] // False positives

use std::{
  sync::{OnceLock, Mutex},
  time::Duration,
  fs,
};

use zeroize::Zeroizing;

use ciphersuite::{group::ff::PrimeField, Ciphersuite, Ristretto};

use serai_client::primitives::NetworkId;

use messages::{CoordinatorMessage, ProcessorMessage};
use serai_message_queue::{Service, Metadata, client::MessageQueue};

use serai_client::Serai;

use dockertest::{
  PullPolicy, Image, LogAction, LogPolicy, LogSource, LogOptions, StartPolicy,
  TestBodySpecification, DockerOperations,
};

#[cfg(test)]
mod tests;

static UNIQUE_ID: OnceLock<Mutex<u16>> = OnceLock::new();

pub fn coordinator_instance(
  name: &str,
  message_queue_key: <Ristretto as Ciphersuite>::F,
) -> TestBodySpecification {
  serai_docker_tests::build("coordinator".to_string());

  TestBodySpecification::with_image(
    Image::with_repository("serai-dev-coordinator").pull_policy(PullPolicy::Never),
  )
  .replace_env(
    [
      ("MESSAGE_QUEUE_KEY".to_string(), hex::encode(message_queue_key.to_repr())),
      ("DB_PATH".to_string(), "./coordinator-db".to_string()),
      ("SERAI_KEY".to_string(), {
        use serai_client::primitives::insecure_pair_from_name;
        hex::encode(&insecure_pair_from_name(name).as_ref().secret.to_bytes()[.. 32])
      }),
      (
        "RUST_LOG".to_string(),
        "serai_coordinator=trace,".to_string() + "tributary_chain=trace," + "tendermint=trace",
      ),
    ]
    .into(),
  )
}

pub fn serai_composition(name: &str) -> TestBodySpecification {
  serai_docker_tests::build("serai".to_string());

  TestBodySpecification::with_image(
    Image::with_repository("serai-dev-serai").pull_policy(PullPolicy::Never),
  )
  .replace_cmd(vec![
    "serai-node".to_string(),
    "--unsafe-rpc-external".to_string(),
    "--rpc-cors".to_string(),
    "all".to_string(),
    "--chain".to_string(),
    "local".to_string(),
    format!("--{}", name.to_lowercase()),
  ])
  .set_publish_all_ports(true)
}

pub type Handles = (String, String, String);
pub fn coordinator_stack(
  name: &str,
) -> (Handles, <Ristretto as Ciphersuite>::F, Vec<TestBodySpecification>) {
  let serai_composition = serai_composition(name);

  let (coord_key, message_queue_keys, message_queue_composition) =
    serai_message_queue_tests::instance();

  let coordinator_composition = coordinator_instance(name, coord_key);

  // Give every item in this stack a unique ID
  // Uses a Mutex as we can't generate a 8-byte random ID without hitting hostname length limits
  let (first, unique_id) = {
    let unique_id_mutex = UNIQUE_ID.get_or_init(|| Mutex::new(0));
    let mut unique_id_lock = unique_id_mutex.lock().unwrap();
    let first = *unique_id_lock == 0;
    let unique_id = hex::encode(unique_id_lock.to_be_bytes());
    *unique_id_lock += 1;
    (first, unique_id)
  };

  let logs_path = [std::env::current_dir().unwrap().to_str().unwrap(), ".test-logs", "coordinator"]
    .iter()
    .collect::<std::path::PathBuf>();
  if first {
    let _ = fs::remove_dir_all(&logs_path);
    fs::create_dir_all(&logs_path).expect("couldn't create logs directory");
    assert!(
      fs::read_dir(&logs_path).expect("couldn't read the logs folder").next().is_none(),
      "logs folder wasn't empty, despite removing it at the start of the run",
    );
  }
  let logs_path = logs_path.to_str().unwrap().to_string();

  let mut compositions = vec![];
  let mut handles = vec![];
  for (name, composition) in [
    ("serai_node", serai_composition),
    ("message_queue", message_queue_composition),
    ("coordinator", coordinator_composition),
  ] {
    let handle = format!("coordinator-{name}-{}", &unique_id);

    compositions.push(
      composition.set_start_policy(StartPolicy::Strict).set_handle(handle.clone()).set_log_options(
        Some(LogOptions {
          action: if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
            LogAction::Forward
          } else {
            LogAction::ForwardToFile { path: logs_path.clone() }
          },
          policy: LogPolicy::Always,
          source: LogSource::Both,
        }),
      ),
    );

    handles.push(handle);
  }

  let coordinator_composition = compositions.last_mut().unwrap();
  coordinator_composition.inject_container_name(handles[0].clone(), "SERAI_HOSTNAME");
  coordinator_composition.inject_container_name(handles[1].clone(), "MESSAGE_QUEUE_RPC");

  (
    (handles[0].clone(), handles[1].clone(), handles[2].clone()),
    message_queue_keys[&NetworkId::Bitcoin],
    compositions,
  )
}

pub struct Processor {
  network: NetworkId,

  serai_rpc: String,
  #[allow(unused)]
  message_queue_handle: String,
  #[allow(unused)]
  coordinator_handle: String,

  next_send_id: u64,
  next_recv_id: u64,
  queue: MessageQueue,
}

impl Processor {
  pub async fn new(
    network: NetworkId,
    ops: &DockerOperations,
    handles: (String, String, String),
    processor_key: <Ristretto as Ciphersuite>::F,
  ) -> Processor {
    let message_queue_rpc = ops.handle(&handles.1).host_port(2287).unwrap();
    let message_queue_rpc = format!("{}:{}", message_queue_rpc.0, message_queue_rpc.1);

    // Sleep until the Substrate RPC starts
    let serai_rpc = ops.handle(&handles.0).host_port(9944).unwrap();
    let serai_rpc = format!("ws://{}:{}", serai_rpc.0, serai_rpc.1);
    // Bound execution to 60 seconds
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = Serai::new(&serai_rpc).await else { continue };
      if client.latest_block_hash().await.is_err() {
        continue;
      }
      break;
    }

    // The Serai RPC may or may not be started
    // Assume it is and continue, so if it's a few seconds late, it's still within tolerance

    Processor {
      network,

      serai_rpc,
      message_queue_handle: handles.1,
      coordinator_handle: handles.2,

      next_send_id: 0,
      next_recv_id: 0,
      queue: MessageQueue::new(
        Service::Processor(network),
        message_queue_rpc,
        Zeroizing::new(processor_key),
      ),
    }
  }

  pub async fn serai(&self) -> Serai {
    Serai::new(&self.serai_rpc).await.unwrap()
  }

  /// Send a message to the coordinator as a processor.
  pub async fn send_message(&mut self, msg: impl Into<ProcessorMessage>) {
    let msg: ProcessorMessage = msg.into();
    self
      .queue
      .queue(
        Metadata {
          from: Service::Processor(self.network),
          to: Service::Coordinator,
          intent: msg.intent(),
        },
        serde_json::to_string(&msg).unwrap().into_bytes(),
      )
      .await;
    self.next_send_id += 1;
  }

  /// Receive a message from the coordinator as a processor.
  pub async fn recv_message(&mut self) -> CoordinatorMessage {
    let msg = tokio::time::timeout(Duration::from_secs(10), self.queue.next(Service::Coordinator))
      .await
      .unwrap();
    assert_eq!(msg.from, Service::Coordinator);
    assert_eq!(msg.id, self.next_recv_id);
    self.queue.ack(Service::Coordinator, msg.id).await;
    self.next_recv_id += 1;
    serde_json::from_slice(&msg.msg).unwrap()
  }
}
