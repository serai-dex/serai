#![allow(clippy::needless_pass_by_ref_mut)] // False positives

use std::sync::{OnceLock, Mutex};

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use ciphersuite::{group::ff::PrimeField, Ciphersuite, Ristretto};

use serai_client::primitives::NetworkId;
use messages::{ProcessorMessage, CoordinatorMessage};
use serai_message_queue::{Service, Metadata, client::MessageQueue};

use dockertest::{
  PullPolicy, Image, LogAction, LogPolicy, LogSource, LogOptions, StartPolicy,
  TestBodySpecification, DockerOperations,
};

mod networks;
pub use networks::*;

#[cfg(test)]
mod tests;

static UNIQUE_ID: OnceLock<Mutex<u16>> = OnceLock::new();

pub fn processor_instance(
  network: NetworkId,
  port: u32,
  message_queue_key: <Ristretto as Ciphersuite>::F,
) -> Vec<TestBodySpecification> {
  let mut entropy = [0; 32];
  OsRng.fill_bytes(&mut entropy);

  let network_str = match network {
    NetworkId::Serai => panic!("starting a processor for Serai"),
    NetworkId::Bitcoin => "bitcoin",
    NetworkId::Ethereum => "ethereum",
    NetworkId::Monero => "monero",
  };
  let image = format!("{network_str}-processor");
  serai_docker_tests::build(image.clone());

  let mut res = vec![TestBodySpecification::with_image(
    Image::with_repository(format!("serai-dev-{image}")).pull_policy(PullPolicy::Never),
  )
  .replace_env(
    [
      ("MESSAGE_QUEUE_KEY".to_string(), hex::encode(message_queue_key.to_repr())),
      ("ENTROPY".to_string(), hex::encode(entropy)),
      ("NETWORK".to_string(), network_str.to_string()),
      ("NETWORK_RPC_LOGIN".to_string(), format!("{RPC_USER}:{RPC_PASS}")),
      ("NETWORK_RPC_PORT".to_string(), port.to_string()),
      ("DB_PATH".to_string(), "./processor-db".to_string()),
      ("RUST_LOG".to_string(), "serai_processor=trace,".to_string()),
    ]
    .into(),
  )];

  if network == NetworkId::Ethereum {
    serai_docker_tests::build("ethereum-relayer".to_string());
    res.push(
      TestBodySpecification::with_image(
        Image::with_repository("serai-dev-ethereum-relayer".to_string())
          .pull_policy(PullPolicy::Never),
      )
      .replace_env(
        [
          ("DB_PATH".to_string(), "./ethereum-relayer-db".to_string()),
          ("RUST_LOG".to_string(), "serai_ethereum_relayer=trace,".to_string()),
        ]
        .into(),
      )
      .set_publish_all_ports(true),
    );
  }

  res
}

pub type Handles = (String, String, String, String);
pub fn processor_stack(
  network: NetworkId,
  network_hostname_override: Option<String>,
) -> (Handles, <Ristretto as Ciphersuite>::F, Vec<TestBodySpecification>) {
  let (network_composition, network_rpc_port) = network_instance(network);

  let (coord_key, message_queue_keys, message_queue_composition) =
    serai_message_queue_tests::instance();

  let mut processor_compositions =
    processor_instance(network, network_rpc_port, message_queue_keys[&network]);

  // Give every item in this stack a unique ID
  // Uses a Mutex as we can't generate a 8-byte random ID without hitting hostname length limits
  let unique_id = {
    let unique_id_mutex = UNIQUE_ID.get_or_init(|| Mutex::new(0));
    let mut unique_id_lock = unique_id_mutex.lock().unwrap();
    let unique_id = *unique_id_lock;
    *unique_id_lock += 1;
    unique_id
  };

  let mut compositions = vec![];
  let mut handles = vec![];
  for (name, composition) in [
    Some((
      match network {
        NetworkId::Serai => unreachable!(),
        NetworkId::Bitcoin => "bitcoin",
        NetworkId::Ethereum => "ethereum",
        NetworkId::Monero => "monero",
      },
      network_composition,
    )),
    Some(("message_queue", message_queue_composition)),
    Some(("processor", processor_compositions.remove(0))),
    processor_compositions.pop().map(|composition| ("relayer", composition)),
  ]
  .into_iter()
  .flatten()
  {
    let handle = format!("processor-{name}-{unique_id}");
    compositions.push(
      composition.set_start_policy(StartPolicy::Strict).set_handle(handle.clone()).set_log_options(
        Some(LogOptions {
          action: LogAction::Forward,
          policy: if handle.contains("-processor-") {
            LogPolicy::Always
          } else {
            LogPolicy::OnError
          },
          source: LogSource::Both,
        }),
      ),
    );
    handles.push(handle);
  }

  let processor_composition = compositions.get_mut(2).unwrap();
  processor_composition.inject_container_name(
    network_hostname_override.unwrap_or_else(|| handles[0].clone()),
    "NETWORK_RPC_HOSTNAME",
  );
  if let Some(hostname) = handles.get(3) {
    processor_composition.inject_container_name(hostname, "ETHEREUM_RELAYER_HOSTNAME");
    processor_composition.modify_env("ETHEREUM_RELAYER_PORT", "20830");
  }
  processor_composition.inject_container_name(handles[1].clone(), "MESSAGE_QUEUE_RPC");

  (
    (
      handles[0].clone(),
      handles[1].clone(),
      handles[2].clone(),
      handles.get(3).cloned().unwrap_or(String::new()),
    ),
    coord_key,
    compositions,
  )
}

#[derive(serde::Deserialize, Debug)]
struct EmptyResponse {}

pub struct Coordinator {
  network: NetworkId,

  network_handle: String,
  #[allow(unused)]
  message_queue_handle: String,
  #[allow(unused)]
  processor_handle: String,
  relayer_handle: String,

  next_send_id: u64,
  next_recv_id: u64,
  queue: MessageQueue,
}

impl Coordinator {
  pub fn new(
    network: NetworkId,
    ops: &DockerOperations,
    handles: Handles,
    coord_key: <Ristretto as Ciphersuite>::F,
  ) -> Coordinator {
    let rpc = ops.handle(&handles.1).host_port(2287).unwrap();
    let rpc = rpc.0.to_string() + ":" + &rpc.1.to_string();

    let res = Coordinator {
      network,

      network_handle: handles.0,
      message_queue_handle: handles.1,
      processor_handle: handles.2,
      relayer_handle: handles.3,

      next_send_id: 0,
      next_recv_id: 0,
      queue: MessageQueue::new(Service::Coordinator, rpc, Zeroizing::new(coord_key)),
    };

    // Sleep for up to a minute in case the external network's RPC has yet to start

    // Gets an async handle to block on since this function plays nicer when it isn't itself async
    {
      let ops = ops.clone();
      let network_handle = res.network_handle.clone();
      std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let handle = runtime.handle();
        let _async = handle.enter();

        let rpc_url = network_rpc(network, &ops, &network_handle);
        let mut iters = 0;
        while iters < 60 {
          match network {
            NetworkId::Bitcoin => {
              use bitcoin_serai::rpc::Rpc;

              // Bitcoin's Rpc::new will test the connection
              if handle.block_on(Rpc::new(rpc_url.clone())).is_ok() {
                break;
              }
            }
            NetworkId::Ethereum => {
              use std::sync::Arc;
              use ethereum_serai::{
                alloy::{
                  simple_request_transport::SimpleRequest,
                  rpc_client::ClientBuilder,
                  provider::{Provider, RootProvider},
                  network::Ethereum,
                },
                deployer::Deployer,
              };

              let provider = Arc::new(RootProvider::<_, Ethereum>::new(
                ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
              ));

              if handle
                .block_on(provider.raw_request::<_, ()>("evm_setAutomine".into(), [false]))
                .is_ok()
              {
                handle.block_on(async {
                  // Deploy the deployer
                  let tx = Deployer::deployment_tx();
                  let signer = tx.recover_signer().unwrap();
                  let (tx, sig, _) = tx.into_parts();

                  provider
                    .raw_request::<_, ()>(
                      "anvil_setBalance".into(),
                      [signer.to_string(), (tx.gas_limit * tx.gas_price).to_string()],
                    )
                    .await
                    .unwrap();

                  let mut bytes = vec![];
                  tx.encode_with_signature_fields(&sig, &mut bytes);
                  let _ = provider.send_raw_transaction(&bytes).await.unwrap();

                  provider.raw_request::<_, ()>("anvil_mine".into(), [96]).await.unwrap();

                  let _ = Deployer::new(provider.clone()).await.unwrap().unwrap();

                  // Sleep until the actual time is ahead of whatever time is in the epoch we just
                  // mined
                  tokio::time::sleep(core::time::Duration::from_secs(30)).await;
                });
                break;
              }
            }
            NetworkId::Monero => {
              use monero_serai::rpc::HttpRpc;

              // Monero's won't, so call get_height
              if handle
                .block_on(HttpRpc::new(rpc_url.clone()))
                .ok()
                .and_then(|rpc| handle.block_on(rpc.get_height()).ok())
                .is_some()
              {
                break;
              }
            }
            NetworkId::Serai => panic!("processor is booting with external network of Serai"),
          }

          println!("external network RPC has yet to boot, waiting 1 sec, attempt {iters}");
          handle.block_on(tokio::time::sleep(core::time::Duration::from_secs(1)));
          iters += 1;
        }
        if iters == 60 {
          panic!("couldn't connect to external network {network:?} after 60s");
        }
      })
      .join()
      .unwrap();
    }

    res
  }

  /// Send a message to a processor as its coordinator.
  pub async fn send_message(&mut self, msg: impl Into<CoordinatorMessage>) {
    let msg: CoordinatorMessage = msg.into();
    self
      .queue
      .queue(
        Metadata {
          from: Service::Coordinator,
          to: Service::Processor(self.network),
          intent: msg.intent(),
        },
        borsh::to_vec(&msg).unwrap(),
      )
      .await;
    self.next_send_id += 1;
  }

  /// Receive a message from a processor as its coordinator.
  pub async fn recv_message(&mut self) -> ProcessorMessage {
    let msg = tokio::time::timeout(
      core::time::Duration::from_secs(20),
      self.queue.next(Service::Processor(self.network)),
    )
    .await
    .unwrap();
    assert_eq!(msg.from, Service::Processor(self.network));
    assert_eq!(msg.id, self.next_recv_id);
    self.queue.ack(Service::Processor(self.network), msg.id).await;
    self.next_recv_id += 1;
    borsh::from_slice(&msg.msg).unwrap()
  }

  pub async fn add_block(&self, ops: &DockerOperations) -> ([u8; 32], Vec<u8>) {
    let rpc_url = network_rpc(self.network, ops, &self.network_handle);
    match self.network {
      NetworkId::Bitcoin => {
        use bitcoin_serai::{
          bitcoin::{consensus::Encodable, network::Network, Script, Address},
          rpc::Rpc,
        };

        // Mine a block
        let rpc = Rpc::new(rpc_url).await.expect("couldn't connect to the Bitcoin RPC");
        rpc
          .rpc_call::<Vec<String>>(
            "generatetoaddress",
            serde_json::json!([1, Address::p2sh(Script::new(), Network::Regtest).unwrap()]),
          )
          .await
          .unwrap();

        // Get it so we can return it
        let hash = rpc.get_block_hash(rpc.get_latest_block_number().await.unwrap()).await.unwrap();
        let block = rpc.get_block(&hash).await.unwrap();
        let mut block_buf = vec![];
        block.consensus_encode(&mut block_buf).unwrap();
        (hash, block_buf)
      }
      NetworkId::Ethereum => {
        use ethereum_serai::alloy::{
          simple_request_transport::SimpleRequest,
          rpc_types::{BlockTransactionsKind, BlockNumberOrTag},
          rpc_client::ClientBuilder,
          provider::{Provider, RootProvider},
          network::Ethereum,
        };

        let provider = RootProvider::<_, Ethereum>::new(
          ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
        );
        let start = provider
          .get_block(BlockNumberOrTag::Latest.into(), BlockTransactionsKind::Hashes)
          .await
          .unwrap()
          .unwrap()
          .header
          .number
          .unwrap();
        // We mine 96 blocks to mine one epoch, then cause its finalization
        provider.raw_request::<_, ()>("anvil_mine".into(), [96]).await.unwrap();
        let end_of_epoch = start + 31;
        let hash = provider
          .get_block(BlockNumberOrTag::Number(end_of_epoch).into(), BlockTransactionsKind::Hashes)
          .await
          .unwrap()
          .unwrap()
          .header
          .hash
          .unwrap();

        let state = provider
          .raw_request::<_, String>("anvil_dumpState".into(), ())
          .await
          .unwrap()
          .into_bytes();
        (hash.into(), state)
      }
      NetworkId::Monero => {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
        use monero_serai::{
          wallet::{
            ViewPair,
            address::{Network, AddressSpec},
          },
          rpc::HttpRpc,
        };

        let rpc = HttpRpc::new(rpc_url).await.expect("couldn't connect to the Monero RPC");
        let _: EmptyResponse = rpc
          .json_rpc_call(
            "generateblocks",
            Some(serde_json::json!({
              "wallet_address": ViewPair::new(
                ED25519_BASEPOINT_POINT,
                Zeroizing::new(Scalar::ONE),
              ).address(Network::Mainnet, AddressSpec::Standard).to_string(),
              "amount_of_blocks": 1,
            })),
          )
          .await
          .unwrap();
        let hash = rpc.get_block_hash(rpc.get_height().await.unwrap() - 1).await.unwrap();
        (hash, rpc.get_block(hash).await.unwrap().serialize())
      }
      NetworkId::Serai => panic!("processor tests adding block to Serai"),
    }
  }

  pub async fn sync(&self, ops: &DockerOperations, others: &[Coordinator]) {
    let rpc_url = network_rpc(self.network, ops, &self.network_handle);
    match self.network {
      NetworkId::Bitcoin => {
        use bitcoin_serai::{bitcoin::consensus::Encodable, rpc::Rpc};

        let rpc = Rpc::new(rpc_url).await.expect("couldn't connect to the Bitcoin RPC");
        let to = rpc.get_latest_block_number().await.unwrap();
        for coordinator in others {
          let other_rpc = Rpc::new(network_rpc(self.network, ops, &coordinator.network_handle))
            .await
            .expect("couldn't connect to the Bitcoin RPC");
          let from = other_rpc.get_latest_block_number().await.unwrap() + 1;

          for b in from ..= to {
            let mut buf = vec![];
            rpc
              .get_block(&rpc.get_block_hash(b).await.unwrap())
              .await
              .unwrap()
              .consensus_encode(&mut buf)
              .unwrap();

            let res: Option<String> = other_rpc
              .rpc_call("submitblock", serde_json::json!([hex::encode(buf)]))
              .await
              .unwrap();
            if let Some(err) = res {
              panic!("submitblock failed: {err}");
            }
          }
        }
      }
      NetworkId::Ethereum => {
        use ethereum_serai::alloy::{
          simple_request_transport::SimpleRequest,
          rpc_types::{BlockTransactionsKind, BlockNumberOrTag},
          rpc_client::ClientBuilder,
          provider::{Provider, RootProvider},
          network::Ethereum,
        };

        let (expected_number, state) = {
          let provider = RootProvider::<_, Ethereum>::new(
            ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
          );

          let expected_number = provider
            .get_block(BlockNumberOrTag::Latest.into(), BlockTransactionsKind::Hashes)
            .await
            .unwrap()
            .unwrap()
            .header
            .number;
          (
            expected_number,
            provider.raw_request::<_, String>("anvil_dumpState".into(), ()).await.unwrap(),
          )
        };

        for coordinator in others {
          let rpc_url = network_rpc(coordinator.network, ops, &coordinator.network_handle);
          let provider = RootProvider::<_, Ethereum>::new(
            ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
          );
          assert!(provider
            .raw_request::<_, bool>("anvil_loadState".into(), &[&state])
            .await
            .unwrap());

          let new_number = provider
            .get_block(BlockNumberOrTag::Latest.into(), BlockTransactionsKind::Hashes)
            .await
            .unwrap()
            .unwrap()
            .header
            .number;

          // TODO: https://github.com/foundry-rs/foundry/issues/7955
          let _ = expected_number;
          let _ = new_number;
          //assert_eq!(expected_number, new_number);
        }
      }
      NetworkId::Monero => {
        use monero_serai::rpc::HttpRpc;

        let rpc = HttpRpc::new(rpc_url).await.expect("couldn't connect to the Monero RPC");
        let to = rpc.get_height().await.unwrap();
        for coordinator in others {
          let other_rpc =
            HttpRpc::new(network_rpc(coordinator.network, ops, &coordinator.network_handle))
              .await
              .expect("couldn't connect to the Monero RPC");

          let from = other_rpc.get_height().await.unwrap();
          for b in from .. to {
            let block =
              rpc.get_block(rpc.get_block_hash(b).await.unwrap()).await.unwrap().serialize();

            let res: serde_json::Value = other_rpc
              .json_rpc_call("submit_block", Some(serde_json::json!([hex::encode(block)])))
              .await
              .unwrap();
            let err = res.get("error");
            if err.is_some() && (err.unwrap() != &serde_json::Value::Null) {
              panic!("failed to submit Monero block: {res}");
            }
          }
        }
      }
      NetworkId::Serai => panic!("processors tests syncing Serai nodes"),
    }
  }

  pub async fn publish_transaction(&self, ops: &DockerOperations, tx: &[u8]) {
    let rpc_url = network_rpc(self.network, ops, &self.network_handle);
    match self.network {
      NetworkId::Bitcoin => {
        use bitcoin_serai::{
          bitcoin::{consensus::Decodable, Transaction},
          rpc::Rpc,
        };

        let rpc =
          Rpc::new(rpc_url).await.expect("couldn't connect to the coordinator's Bitcoin RPC");
        rpc.send_raw_transaction(&Transaction::consensus_decode(&mut &*tx).unwrap()).await.unwrap();
      }
      NetworkId::Ethereum => {
        use ethereum_serai::alloy::{
          simple_request_transport::SimpleRequest,
          rpc_client::ClientBuilder,
          provider::{Provider, RootProvider},
          network::Ethereum,
        };

        let provider = RootProvider::<_, Ethereum>::new(
          ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
        );
        let _ = provider.send_raw_transaction(tx).await.unwrap();
      }
      NetworkId::Monero => {
        use monero_serai::{transaction::Transaction, rpc::HttpRpc};

        let rpc =
          HttpRpc::new(rpc_url).await.expect("couldn't connect to the coordinator's Monero RPC");
        rpc.publish_transaction(&Transaction::read(&mut &*tx).unwrap()).await.unwrap();
      }
      NetworkId::Serai => panic!("processor tests broadcasting block to Serai"),
    }
  }

  pub async fn publish_eventuality_completion(&self, ops: &DockerOperations, tx: &[u8]) {
    match self.network {
      NetworkId::Bitcoin | NetworkId::Monero => self.publish_transaction(ops, tx).await,
      NetworkId::Ethereum => (),
      NetworkId::Serai => panic!("processor tests broadcasting block to Serai"),
    }
  }

  pub async fn get_published_transaction(
    &self,
    ops: &DockerOperations,
    tx: &[u8],
  ) -> Option<Vec<u8>> {
    let rpc_url = network_rpc(self.network, ops, &self.network_handle);
    match self.network {
      NetworkId::Bitcoin => {
        use bitcoin_serai::{bitcoin::consensus::Encodable, rpc::Rpc};

        let rpc =
          Rpc::new(rpc_url).await.expect("couldn't connect to the coordinator's Bitcoin RPC");

        // Bitcoin publishes a 0-byte TX ID to reduce variables
        // Accordingly, read the mempool to find the (presumed relevant) TX
        let entries: Vec<String> =
          rpc.rpc_call("getrawmempool", serde_json::json!([false])).await.unwrap();
        assert_eq!(entries.len(), 1, "more than one entry in the mempool, so unclear which to get");

        let mut hash = [0; 32];
        hash.copy_from_slice(&hex::decode(&entries[0]).unwrap());
        if let Ok(tx) = rpc.get_transaction(&hash).await {
          let mut buf = vec![];
          tx.consensus_encode(&mut buf).unwrap();
          Some(buf)
        } else {
          None
        }
      }
      NetworkId::Ethereum => {
        /*
        let provider = RootProvider::<_, Ethereum>::new(
          ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
        );
        let mut hash = [0; 32];
        hash.copy_from_slice(tx);
        let tx = provider.get_transaction_by_hash(hash.into()).await.unwrap()?;
        let (tx, sig, _) = Signed::<TxLegacy>::try_from(tx).unwrap().into_parts();
        let mut bytes = vec![];
        tx.encode_with_signature_fields(&sig, &mut bytes);
        Some(bytes)
        */

        // This is being passed a signature. We need to check the relayer has a TX with this
        // signature

        use tokio::{
          io::{AsyncReadExt, AsyncWriteExt},
          net::TcpStream,
        };

        let (ip, port) = ops.handle(&self.relayer_handle).host_port(20831).unwrap();
        let relayer_url = format!("{ip}:{port}");

        let mut socket = TcpStream::connect(&relayer_url).await.unwrap();
        // Iterate over every published command
        for i in 1 .. u32::MAX {
          socket.write_all(&i.to_le_bytes()).await.unwrap();

          let mut recvd_len = [0; 4];
          socket.read_exact(&mut recvd_len).await.unwrap();
          if recvd_len == [0; 4] {
            break;
          }

          let mut msg = vec![0; usize::try_from(u32::from_le_bytes(recvd_len)).unwrap()];
          socket.read_exact(&mut msg).await.unwrap();
          for start_pos in 0 .. msg.len() {
            if (start_pos + tx.len()) > msg.len() {
              break;
            }
            if &msg[start_pos .. (start_pos + tx.len())] == tx {
              return Some(msg);
            }
          }
        }

        None
      }
      NetworkId::Monero => {
        use monero_serai::rpc::HttpRpc;

        let rpc =
          HttpRpc::new(rpc_url).await.expect("couldn't connect to the coordinator's Monero RPC");
        let mut hash = [0; 32];
        hash.copy_from_slice(tx);
        if let Ok(tx) = rpc.get_transaction(hash).await {
          Some(tx.serialize())
        } else {
          None
        }
      }
      NetworkId::Serai => panic!("processor tests broadcasting block to Serai"),
    }
  }
}
