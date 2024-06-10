#![allow(clippy::needless_pass_by_ref_mut)] // False positives

use std::{
  sync::{OnceLock, Arc},
  time::Duration,
};

use tokio::{
  task::AbortHandle,
  sync::{Mutex as AsyncMutex, mpsc},
};

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

use dockertest::{PullPolicy, Image, TestBodySpecification, DockerOperations};

#[cfg(test)]
mod tests;

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

pub fn serai_composition(name: &str, fast_epoch: bool) -> TestBodySpecification {
  (if fast_epoch {
    serai_docker_tests::build("serai-fast-epoch".to_string());
    TestBodySpecification::with_image(
      Image::with_repository("serai-dev-serai-fast-epoch").pull_policy(PullPolicy::Never),
    )
  } else {
    serai_docker_tests::build("serai".to_string());
    TestBodySpecification::with_image(
      Image::with_repository("serai-dev-serai").pull_policy(PullPolicy::Never),
    )
  })
  .replace_env(
    [("SERAI_NAME".to_string(), name.to_lowercase()), ("KEY".to_string(), " ".to_string())].into(),
  )
  .set_publish_all_ports(true)
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Handles {
  pub(crate) serai: String,
  pub(crate) message_queue: String,
}

pub struct Processor {
  network: NetworkId,

  serai_rpc: String,
  #[allow(unused)]
  handles: Handles,

  msgs: mpsc::UnboundedReceiver<messages::CoordinatorMessage>,
  queue_for_sending: MessageQueue,
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
    handles: Handles,
    processor_key: <Ristretto as Ciphersuite>::F,
  ) -> Processor {
    let message_queue_rpc = ops.handle(&handles.message_queue).host_port(2287).unwrap();
    let message_queue_rpc = format!("{}:{}", message_queue_rpc.0, message_queue_rpc.1);

    // Sleep until the Substrate RPC starts
    let serai_rpc = ops.handle(&handles.serai).host_port(9944).unwrap();
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

    // Create the queue
    let mut queue = (
      0,
      Arc::new(MessageQueue::new(
        Service::Processor(network),
        message_queue_rpc.clone(),
        Zeroizing::new(processor_key),
      )),
    );

    let (msg_send, msg_recv) = mpsc::unbounded_channel();

    let substrate_key = Arc::new(AsyncMutex::new(None));
    let mut res = Processor {
      network,

      serai_rpc,
      handles,

      queue_for_sending: MessageQueue::new(
        Service::Processor(network),
        message_queue_rpc,
        Zeroizing::new(processor_key),
      ),
      msgs: msg_recv,
      abort_handle: None,

      substrate_key: substrate_key.clone(),
    };

    // Spawn a task to handle cosigns and forward messages as appropriate
    let abort_handle = tokio::spawn({
      async move {
        loop {
          // Get new messages
          let (next_recv_id, queue) = &mut queue;
          let msg = queue.next(Service::Coordinator).await;
          assert_eq!(msg.from, Service::Coordinator);
          assert_eq!(msg.id, *next_recv_id);
          queue.ack(Service::Coordinator, msg.id).await;
          *next_recv_id += 1;

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
            continue;
          }

          if !is_cosign_message(&msg_msg) {
            msg_send.send(msg_msg).unwrap();
            continue;
          }
          let msg = msg_msg;

          let send_message = |msg: ProcessorMessage| async move {
            queue
              .queue(
                Metadata {
                  from: Service::Processor(network),
                  to: Service::Coordinator,
                  intent: msg.intent(),
                },
                borsh::to_vec(&msg).unwrap(),
              )
              .await;
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
              messages::coordinator::CoordinatorMessage::CosignSubstrateBlock { id, block_number },
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
              send_message(
                messages::coordinator::ProcessorMessage::CosignPreprocess {
                  id: id.clone(),
                  preprocesses: vec![[raw_i; 64]],
                }
                .into(),
              )
              .await;
            }
            CoordinatorMessage::Coordinator(
              messages::coordinator::CoordinatorMessage::SubstratePreprocesses { id, .. },
            ) => {
              // TODO: Assert the ID matches CURRENT_COSIGN
              // TODO: Verify the received preprocesses
              send_message(
                messages::coordinator::ProcessorMessage::SubstrateShare {
                  id,
                  shares: vec![[raw_i; 32]],
                }
                .into(),
              )
              .await;
            }
            CoordinatorMessage::Coordinator(
              messages::coordinator::CoordinatorMessage::SubstrateShares { .. },
            ) => {
              // TODO: Assert the ID matches CURRENT_COSIGN
              // TODO: Verify the shares

              let block_number = current_cosign.as_ref().unwrap().block_number;
              let block = current_cosign.as_ref().unwrap().block;

              let substrate_key = substrate_key.lock().await.clone().unwrap();

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

              send_message(
                messages::coordinator::ProcessorMessage::CosignedBlock {
                  block_number,
                  block,
                  signature: signature.0.to_vec(),
                }
                .into(),
              )
              .await;
            }
            _ => panic!("unexpected message passed is_cosign_message"),
          }
        }
      }
    })
    .abort_handle();

    res.abort_handle = Some(Arc::new(abort_handle));

    res
  }

  pub async fn serai(&self) -> Serai {
    Serai::new(self.serai_rpc.clone()).await.unwrap()
  }

  /// Send a message to the coordinator as a processor.
  pub async fn send_message(&mut self, msg: impl Into<ProcessorMessage>) {
    let msg: ProcessorMessage = msg.into();

    self
      .queue_for_sending
      .queue(
        Metadata {
          from: Service::Processor(self.network),
          to: Service::Coordinator,
          intent: msg.intent(),
        },
        borsh::to_vec(&msg).unwrap(),
      )
      .await;
  }

  /// Receive a message from the coordinator as a processor.
  pub async fn recv_message(&mut self) -> CoordinatorMessage {
    // Set a timeout of 20 minutes to allow effectively any protocol to occur without a fear of
    // an arbitrary timeout cutting it short
    tokio::time::timeout(Duration::from_secs(20 * 60), self.msgs.recv()).await.unwrap().unwrap()
  }

  pub async fn set_substrate_key(
    &mut self,
    substrate_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) {
    *self.substrate_key.lock().await = Some(substrate_key);
  }
}
