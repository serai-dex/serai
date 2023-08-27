use std::{
  sync::{OnceLock, Mutex},
  fs,
};

use serai_client::primitives::NetworkId;

use dockertest::{
  LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, Composition, DockerOperations,
};

#[cfg(test)]
mod tests;

static UNIQUE_ID: OnceLock<Mutex<u16>> = OnceLock::new();

use serai_processor_tests::{network_instance, processor_instance};
use serai_message_queue_tests::instance as message_queue_instance;
use serai_coordinator_tests::{coordinator_instance, serai_composition};

#[allow(unused)]
pub struct Handles {
  bitcoin: (String, u32),
  bitcoin_processor: String,
  monero: (String, u32),
  monero_processor: String,
  message_queue: String,
  coordinator: String,
  serai: String,
}

pub fn full_stack(name: &str) -> (Handles, Vec<Composition>) {
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
    let unique_id = hex::encode(unique_id_lock.to_be_bytes());
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
  for composition in [
    message_queue_composition,
    bitcoin_composition,
    bitcoin_processor_composition,
    monero_composition,
    monero_processor_composition,
    coordinator_composition,
    serai_composition,
  ] {
    let name = format!("{}-{}", composition.handle(), &unique_id);

    compositions.push(
      composition
        .with_start_policy(StartPolicy::Strict)
        .with_container_name(name.clone())
        .with_log_options(Some(LogOptions {
          action: if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
            LogAction::Forward
          } else {
            LogAction::ForwardToFile { path: logs_path.clone() }
          },
          policy: LogPolicy::Always,
          source: LogSource::Both,
        })),
    );

    handles.push(compositions.last().unwrap().handle());
  }
  let handles = Handles {
    message_queue: handles.remove(0),
    bitcoin: (handles.remove(0), bitcoin_port),
    bitcoin_processor: handles.remove(0),
    monero: (handles.remove(0), monero_port),
    monero_processor: handles.remove(0),
    coordinator: handles.remove(0),
    serai: handles.remove(0),
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
