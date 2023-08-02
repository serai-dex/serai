#![allow(clippy::needless_pass_by_ref_mut)] // False positives

use std::sync::{OnceLock, Mutex};

use ciphersuite::{group::ff::PrimeField, Ciphersuite, Ristretto};

use serai_client::primitives::NetworkId;

use dockertest::{
  PullPolicy, Image, LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, Composition,
};

#[cfg(test)]
mod tests;

static UNIQUE_ID: OnceLock<Mutex<u16>> = OnceLock::new();

pub fn coordinator_instance(message_queue_key: <Ristretto as Ciphersuite>::F) -> Composition {
  serai_docker_tests::build("coordinator".to_string());

  Composition::with_image(
    Image::with_repository("serai-dev-coordinator").pull_policy(PullPolicy::Never),
  )
  .with_env(
    [
      ("MESSAGE_QUEUE_KEY".to_string(), hex::encode(message_queue_key.to_repr())),
      ("DB_PATH".to_string(), "./coordinator-db".to_string()),
    ]
    .into(),
  )
}

pub fn serai_composition(name: &str) -> Composition {
  serai_docker_tests::build("serai".to_string());

  Composition::with_image(Image::with_repository("serai-dev-serai").pull_policy(PullPolicy::Never))
    .with_cmd(vec![
      "serai-node".to_string(),
      "--unsafe-rpc-external".to_string(),
      "--rpc-cors".to_string(),
      "all".to_string(),
      "--chain".to_string(),
      "devnet".to_string(),
      format!("--{name}"),
    ])
}

pub type Handles = (String, String, String);
pub fn coordinator_stack(name: &str) -> (Handles, <Ristretto as Ciphersuite>::F, Vec<Composition>) {
  let serai_composition = serai_composition(name);

  let (coord_key, message_queue_keys, message_queue_composition) =
    serai_message_queue_tests::instance();

  let coordinator_composition = coordinator_instance(message_queue_keys[&NetworkId::Bitcoin]);

  // Give every item in this stack a unique ID
  // Uses a Mutex as we can't generate a 8-byte random ID without hitting hostname length limits
  let unique_id = {
    let unique_id_mutex = UNIQUE_ID.get_or_init(|| Mutex::new(0));
    let mut unique_id_lock = unique_id_mutex.lock().unwrap();
    let unique_id = hex::encode(unique_id_lock.to_be_bytes());
    *unique_id_lock += 1;
    unique_id
  };

  let mut compositions = vec![];
  let mut handles = vec![];
  for composition in [serai_composition, message_queue_composition, coordinator_composition] {
    let handle = composition.handle();
    compositions.push(
      composition
        .with_start_policy(StartPolicy::Strict)
        .with_container_name(format!("{handle}-{}", &unique_id))
        .with_log_options(Some(LogOptions {
          action: LogAction::Forward,
          policy: if handle.contains("coordinator") {
            LogPolicy::Always
          } else {
            LogPolicy::OnError
          },
          source: LogSource::Both,
        })),
    );
    handles.push(compositions.last().unwrap().handle());
  }

  let coordinator_composition = compositions.last_mut().unwrap();
  coordinator_composition.inject_container_name(handles.remove(0), "SERAI_HOSTNAME");
  coordinator_composition.inject_container_name(handles.remove(0), "MESSAGE_QUEUE_RPC");

  (
    (compositions[0].handle(), compositions[1].handle(), compositions[2].handle()),
    coord_key,
    compositions,
  )
}
