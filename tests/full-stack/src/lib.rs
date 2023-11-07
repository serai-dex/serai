use std::{
  sync::{OnceLock, Mutex},
  time::Duration,
  fs,
};

use serai_client::{primitives::NetworkId, Serai};

use dockertest::{
  LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, TestBodySpecification, DockerOperations,
};

#[cfg(test)]
mod tests;

static UNIQUE_ID: OnceLock<Mutex<u16>> = OnceLock::new();

use serai_processor_tests::{RPC_USER, RPC_PASS, network_instance, processor_instance};
use serai_message_queue_tests::instance as message_queue_instance;
use serai_coordinator_tests::{coordinator_instance, serai_composition};

#[allow(unused)]
#[derive(Clone, Debug)]
pub struct Handles {
  bitcoin: (String, u32),
  bitcoin_processor: String,
  monero: (String, u32),
  monero_processor: String,
  message_queue: String,
  coordinator: String,
  serai: String,
}

pub fn full_stack(name: &str) -> (Handles, Vec<TestBodySpecification>) {
  let (coord_key, message_queue_keys, message_queue_composition) = message_queue_instance();

  let (bitcoin_composition, bitcoin_port) = network_instance(NetworkId::Bitcoin);
  let bitcoin_processor_composition =
    processor_instance(NetworkId::Bitcoin, bitcoin_port, message_queue_keys[&NetworkId::Bitcoin]);

  let (monero_composition, monero_port) = network_instance(NetworkId::Monero);
  let monero_processor_composition =
    processor_instance(NetworkId::Monero, monero_port, message_queue_keys[&NetworkId::Monero]);

  let coordinator_composition = coordinator_instance(name, coord_key);
  let serai_composition = serai_composition(name);

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

  let logs_path = [std::env::current_dir().unwrap().to_str().unwrap(), ".test-logs", "full-stack"]
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
    ("message_queue", message_queue_composition),
    ("bitcoin", bitcoin_composition),
    ("bitcoin_processor", bitcoin_processor_composition),
    ("monero", monero_composition),
    ("monero_processor", monero_processor_composition),
    ("coordinator", coordinator_composition),
    ("serai", serai_composition),
  ] {
    let handle = format!("full_stack-{name}-{unique_id}");
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
  let handles = Handles {
    message_queue: handles[0].clone(),
    bitcoin: (handles[1].clone(), bitcoin_port),
    bitcoin_processor: handles[2].clone(),
    monero: (handles[3].clone(), monero_port),
    monero_processor: handles[4].clone(),
    coordinator: handles[5].clone(),
    serai: handles[6].clone(),
  };

  {
    let bitcoin_processor_composition = compositions.get_mut(2).unwrap();
    bitcoin_processor_composition
      .inject_container_name(handles.message_queue.clone(), "MESSAGE_QUEUE_RPC");
    bitcoin_processor_composition
      .inject_container_name(handles.bitcoin.0.clone(), "NETWORK_RPC_HOSTNAME");
  }

  {
    let monero_processor_composition = compositions.get_mut(4).unwrap();
    monero_processor_composition
      .inject_container_name(handles.message_queue.clone(), "MESSAGE_QUEUE_RPC");
    monero_processor_composition
      .inject_container_name(handles.monero.0.clone(), "NETWORK_RPC_HOSTNAME");
  }

  let coordinator_composition = compositions.get_mut(5).unwrap();
  coordinator_composition.inject_container_name(handles.message_queue.clone(), "MESSAGE_QUEUE_RPC");
  coordinator_composition.inject_container_name(handles.serai.clone(), "SERAI_HOSTNAME");

  (handles, compositions)
}

impl Handles {
  pub async fn serai(&self, ops: &DockerOperations) -> Serai {
    let serai_rpc = ops.handle(&self.serai).host_port(9944).unwrap();
    let serai_rpc = format!("ws://{}:{}", serai_rpc.0, serai_rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = Serai::new(&serai_rpc).await else { continue };
      if client.latest_block_hash().await.is_err() {
        continue;
      }
      return client;
    }
    panic!("serai RPC server wasn't available after 60s");
  }

  pub async fn bitcoin(&self, ops: &DockerOperations) -> bitcoin_serai::rpc::Rpc {
    let rpc = ops.handle(&self.bitcoin.0).host_port(self.bitcoin.1).unwrap();
    let rpc = format!("http://{RPC_USER}:{RPC_PASS}@{}:{}", rpc.0, rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = bitcoin_serai::rpc::Rpc::new(rpc.clone()).await else { continue };
      return client;
    }
    panic!("bitcoin RPC server wasn't available after 60s");
  }

  pub async fn monero(
    &self,
    ops: &DockerOperations,
  ) -> monero_serai::rpc::Rpc<monero_serai::rpc::HttpRpc> {
    use monero_serai::rpc::HttpRpc;

    let rpc = ops.handle(&self.monero.0).host_port(self.monero.1).unwrap();
    let rpc = format!("http://{RPC_USER}:{RPC_PASS}@{}:{}", rpc.0, rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = HttpRpc::new(rpc.clone()).await else { continue };
      if client.get_height().await.is_err() {
        continue;
      }
      return client;
    }
    panic!("monero RPC server wasn't available after 60s");
  }
}
