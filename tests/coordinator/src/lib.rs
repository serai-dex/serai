#![allow(clippy::needless_pass_by_ref_mut)] // False positives

use std::{
  sync::{OnceLock, Arc, Mutex},
  time::Duration,
  fs,
};

use tokio::{task::AbortHandle, sync::Mutex as AsyncMutex};

use rand_core::{RngCore, OsRng};

use zeroize::Zeroizing;

use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding},
  Ciphersuite, Ristretto,
};

use serai_client::primitives::NetworkId;

use messages::{
  coordinator::{SubstrateSignableId, SubstrateSignId, cosign_block_msg},
  CoordinatorMessage, ProcessorMessage,
};
use serai_message_queue::{Service, Metadata, client::MessageQueue};

use serai_client::{primitives::Signature, Serai};

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
    let unique_id = *unique_id_lock;
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
    let handle = format!("coordinator-{name}-{unique_id}");

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

fn is_cosign_message(msg: &CoordinatorMessage) -> bool {
  matches!(
    msg,
    CoordinatorMessage::Coordinator(
      messages::coordinator::CoordinatorMessage::CosignSubstrateBlock { .. }
    )
  ) || matches!(
    msg,
    CoordinatorMessage::Coordinator(
      messages::coordinator::CoordinatorMessage::SubstratePreprocesses {
        id: SubstrateSignId { id: SubstrateSignableId::CosigningSubstrateBlock(_), .. },
        ..
      }
    ),
  ) || matches!(
    msg,
    CoordinatorMessage::Coordinator(messages::coordinator::CoordinatorMessage::SubstrateShares {
      id: SubstrateSignId { id: SubstrateSignableId::CosigningSubstrateBlock(_), .. },
      ..
    }),
  )
}

#[derive(Clone)]
pub struct Processor {
  network: NetworkId,

  serai_rpc: String,
  #[allow(unused)]
  message_queue_handle: String,
  #[allow(unused)]
  coordinator_handle: String,

  queue: Arc<AsyncMutex<(u64, u64, MessageQueue)>>,
  abort_handle: Option<Arc<AbortHandle>>,

  substrate_key: Arc<AsyncMutex<Option<Zeroizing<<Ristretto as Ciphersuite>::F>>>>,
}

impl Drop for Processor {
  fn drop(&mut self) {
    if let Some(abort_handle) = self.abort_handle.take() {
      abort_handle.abort();
    };
  }
}

impl Processor {
  pub async fn new(
    raw_i: u8,
    network: NetworkId,
    ops: &DockerOperations,
    handles: (String, String, String),
    processor_key: <Ristretto as Ciphersuite>::F,
  ) -> Processor {
    let message_queue_rpc = ops.handle(&handles.1).host_port(2287).unwrap();
    let message_queue_rpc = format!("{}:{}", message_queue_rpc.0, message_queue_rpc.1);

    // Sleep until the Substrate RPC starts
    let serai_rpc = ops.handle(&handles.0).host_port(9944).unwrap();
    let serai_rpc = format!("http://{}:{}", serai_rpc.0, serai_rpc.1);
    // Bound execution to 60 seconds
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = Serai::new(serai_rpc.clone()).await else { continue };
      if client.latest_finalized_block_hash().await.is_err() {
        continue;
      }
      break;
    }

    // The Serai RPC may or may not be started
    // Assume it is and continue, so if it's a few seconds late, it's still within tolerance

    let mut res = Processor {
      network,

      serai_rpc,
      message_queue_handle: handles.1,
      coordinator_handle: handles.2,

      queue: Arc::new(AsyncMutex::new((
        0,
        0,
        MessageQueue::new(
          Service::Processor(network),
          message_queue_rpc,
          Zeroizing::new(processor_key),
        ),
      ))),
      abort_handle: None,

      substrate_key: Arc::new(AsyncMutex::new(None)),
    };

    // Handle any cosigns which come up
    res.abort_handle = Some(Arc::new(
      tokio::spawn({
        let mut res = res.clone();
        async move {
          loop {
            tokio::task::yield_now().await;

            let msg = {
              let mut queue_lock = res.queue.lock().await;
              let (_, next_recv_id, queue) = &mut *queue_lock;
              let Ok(msg) =
                tokio::time::timeout(Duration::from_secs(1), queue.next(Service::Coordinator))
                  .await
              else {
                continue;
              };
              assert_eq!(msg.from, Service::Coordinator);
              assert_eq!(msg.id, *next_recv_id);

              let msg_msg = borsh::from_slice(&msg.msg).unwrap();
              // Remove any BatchReattempts clogging the pipe
              // TODO: Set up a wrapper around serai-client so we aren't throwing this away yet
              // leave it for the tests
              if matches!(
                msg_msg,
                messages::CoordinatorMessage::Coordinator(
                  messages::coordinator::CoordinatorMessage::BatchReattempt { .. }
                )
              ) {
                queue.ack(Service::Coordinator, msg.id).await;
                *next_recv_id += 1;
                continue;
              }
              if !is_cosign_message(&msg_msg) {
                continue;
              };
              queue.ack(Service::Coordinator, msg.id).await;
              *next_recv_id += 1;
              msg_msg
            };

            struct CurrentCosign {
              block_number: u64,
              block: [u8; 32],
            }
            static CURRENT_COSIGN: OnceLock<AsyncMutex<Option<CurrentCosign>>> = OnceLock::new();
            let mut current_cosign =
              CURRENT_COSIGN.get_or_init(|| AsyncMutex::new(None)).lock().await;
            match msg {
              // If this is a CosignSubstrateBlock, reset the CurrentCosign
              // While technically, each processor should individually track the current cosign,
              // this is fine for current testing purposes
              CoordinatorMessage::Coordinator(
                messages::coordinator::CoordinatorMessage::CosignSubstrateBlock {
                  id,
                  block_number,
                },
              ) => {
                let SubstrateSignId {
                  id: SubstrateSignableId::CosigningSubstrateBlock(block), ..
                } = id
                else {
                  panic!("CosignSubstrateBlock didn't have CosigningSubstrateBlock ID")
                };

                let new_cosign = CurrentCosign { block_number, block };
                if current_cosign.is_none() || (current_cosign.as_ref().unwrap().block != block) {
                  *current_cosign = Some(new_cosign);
                }
                res
                  .send_message(messages::coordinator::ProcessorMessage::CosignPreprocess {
                    id: id.clone(),
                    preprocesses: vec![[raw_i; 64]],
                  })
                  .await;
              }
              CoordinatorMessage::Coordinator(
                messages::coordinator::CoordinatorMessage::SubstratePreprocesses { id, .. },
              ) => {
                // TODO: Assert the ID matches CURRENT_COSIGN
                // TODO: Verify the received preprocesses
                res
                  .send_message(messages::coordinator::ProcessorMessage::SubstrateShare {
                    id,
                    shares: vec![[raw_i; 32]],
                  })
                  .await;
              }
              CoordinatorMessage::Coordinator(
                messages::coordinator::CoordinatorMessage::SubstrateShares { .. },
              ) => {
                // TODO: Assert the ID matches CURRENT_COSIGN
                // TODO: Verify the shares

                let block_number = current_cosign.as_ref().unwrap().block_number;
                let block = current_cosign.as_ref().unwrap().block;

                let substrate_key = res.substrate_key.lock().await.clone().unwrap();

                // Expand to a key pair as Schnorrkel expects
                // It's the private key + 32-bytes of entropy for nonces + the public key
                let mut schnorrkel_key_pair = [0; 96];
                schnorrkel_key_pair[.. 32].copy_from_slice(&substrate_key.to_repr());
                OsRng.fill_bytes(&mut schnorrkel_key_pair[32 .. 64]);
                schnorrkel_key_pair[64 ..].copy_from_slice(
                  &(<Ristretto as Ciphersuite>::generator() * *substrate_key).to_bytes(),
                );
                let signature = Signature(
                  schnorrkel::keys::Keypair::from_bytes(&schnorrkel_key_pair)
                    .unwrap()
                    .sign_simple(b"substrate", &cosign_block_msg(block_number, block))
                    .to_bytes(),
                );

                res
                  .send_message(messages::coordinator::ProcessorMessage::CosignedBlock {
                    block_number,
                    block,
                    signature: signature.0.to_vec(),
                  })
                  .await;
              }
              _ => panic!("unexpected message passed is_cosign_message"),
            }
          }
        }
      })
      .abort_handle(),
    ));

    res
  }

  pub async fn serai(&self) -> Serai {
    Serai::new(self.serai_rpc.clone()).await.unwrap()
  }

  /// Send a message to the coordinator as a processor.
  pub async fn send_message(&mut self, msg: impl Into<ProcessorMessage>) {
    let msg: ProcessorMessage = msg.into();

    let mut queue_lock = self.queue.lock().await;
    let (next_send_id, _, queue) = &mut *queue_lock;
    queue
      .queue(
        Metadata {
          from: Service::Processor(self.network),
          to: Service::Coordinator,
          intent: msg.intent(),
        },
        borsh::to_vec(&msg).unwrap(),
      )
      .await;
    *next_send_id += 1;
  }

  async fn recv_message_inner(&mut self) -> CoordinatorMessage {
    loop {
      tokio::task::yield_now().await;

      let mut queue_lock = self.queue.lock().await;
      let (_, next_recv_id, queue) = &mut *queue_lock;
      let msg = queue.next(Service::Coordinator).await;
      assert_eq!(msg.from, Service::Coordinator);
      assert_eq!(msg.id, *next_recv_id);

      // If this is a cosign message, let the cosign task handle it
      let msg_msg = borsh::from_slice(&msg.msg).unwrap();
      if is_cosign_message(&msg_msg) {
        continue;
      }

      queue.ack(Service::Coordinator, msg.id).await;
      *next_recv_id += 1;
      return msg_msg;
    }
  }

  /// Receive a message from the coordinator as a processor.
  pub async fn recv_message(&mut self) -> CoordinatorMessage {
    // Set a timeout of 15 minutes to allow effectively any protocol to occur without a fear of
    // an arbitrary timeout cutting it short
    tokio::time::timeout(Duration::from_secs(15 * 60), self.recv_message_inner()).await.unwrap()
  }

  pub async fn set_substrate_key(
    &mut self,
    substrate_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) {
    *self.substrate_key.lock().await = Some(substrate_key);
  }
}
