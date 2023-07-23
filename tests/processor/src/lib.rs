use std::sync::{OnceLock, Mutex};

use rand_core::{RngCore, OsRng};

use ciphersuite::{group::ff::PrimeField, Ciphersuite, Ristretto};

use serai_primitives::NetworkId;

use dockertest::{
  PullPolicy, Image, LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, Composition,
};

const RPC_USER: &str = "serai";
const RPC_PASS: &str = "seraidex";

static UNIQUE_ID: OnceLock<Mutex<u16>> = OnceLock::new();

pub fn bitcoin_instance() -> (Composition, u16) {
  serai_docker_tests::build("bitcoin".to_string());

  (
    Composition::with_image(
      Image::with_repository("serai-dev-bitcoin").pull_policy(PullPolicy::Never),
    )
    .with_cmd(vec![
      "bitcoind".to_string(),
      "-txindex".to_string(),
      "-regtest".to_string(),
      format!("-rpcuser={RPC_USER}"),
      format!("-rpcpassword={RPC_PASS}"),
      "-rpcbind=0.0.0.0".to_string(),
      "-rpcallowip=0.0.0.0/0".to_string(),
      "-rpcport=8332".to_string(),
    ]),
    8332,
  )
}

pub fn monero_instance() -> (Composition, u16) {
  serai_docker_tests::build("monero".to_string());

  (
    Composition::with_image(
      Image::with_repository("serai-dev-monero").pull_policy(PullPolicy::Never),
    )
    .with_cmd(vec![
      "monerod".to_string(),
      "--regtest".to_string(),
      "--offline".to_string(),
      "--fixed-difficulty=1".to_string(),
      "--rpc-bind-ip=0.0.0.0".to_string(),
      format!("--rpc-login={RPC_USER}:{RPC_PASS}"),
      "--rpc-access-control-origins=*".to_string(),
      "--confirm-external-bind".to_string(),
      "--non-interactive".to_string(),
    ])
    .with_start_policy(StartPolicy::Strict),
    18081,
  )
}

pub fn network_instance(network: NetworkId) -> (Composition, u16) {
  match network {
    NetworkId::Bitcoin => bitcoin_instance(),
    NetworkId::Ethereum => todo!(),
    NetworkId::Monero => monero_instance(),
    NetworkId::Serai => {
      panic!("Serai is not a valid network to spawn an instance of for a processor")
    }
  }
}

pub fn processor_instance(
  network: NetworkId,
  port: u16,
  message_queue_key: <Ristretto as Ciphersuite>::F,
) -> Composition {
  serai_docker_tests::build("processor".to_string());

  let mut entropy = [0; 32];
  OsRng.fill_bytes(&mut entropy);

  Composition::with_image(
    Image::with_repository("serai-dev-processor").pull_policy(PullPolicy::Never),
  )
  .with_env(
    [
      ("MESSAGE_QUEUE_KEY".to_string(), hex::encode(message_queue_key.to_repr())),
      ("ENTROPY".to_string(), hex::encode(entropy)),
      (
        "NETWORK".to_string(),
        (match network {
          NetworkId::Serai => panic!("starting a processor for Serai"),
          NetworkId::Bitcoin => "bitcoin",
          NetworkId::Ethereum => "ethereum",
          NetworkId::Monero => "monero",
        })
        .to_string(),
      ),
      ("NETWORK_RPC_LOGIN".to_string(), format!("{RPC_USER}:{RPC_PASS}")),
      ("NETWORK_RPC_PORT".to_string(), port.to_string()),
      ("DB_PATH".to_string(), "./processor-db".to_string()),
    ]
    .into(),
  )
}

pub fn processor_stack(
  network: NetworkId,
) -> (String, <Ristretto as Ciphersuite>::F, Vec<Composition>) {
  let (network_composition, network_rpc_port) = network_instance(network);

  let (coord_key, message_queue_keys, message_queue_composition) =
    serai_message_queue_tests::instance();

  let processor_composition =
    processor_instance(network, network_rpc_port, message_queue_keys[&network]);

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
  for composition in [network_composition, message_queue_composition, processor_composition] {
    let handle = composition.handle();
    compositions.push(
      composition
        .with_start_policy(StartPolicy::Strict)
        .with_container_name(format!("{handle}-{}", &unique_id))
        .with_log_options(Some(LogOptions {
          action: LogAction::Forward,
          policy: if handle.contains("processor") { LogPolicy::Always } else { LogPolicy::OnError },
          source: LogSource::Both,
        })),
    );
    handles.push(compositions.last().unwrap().handle());
  }

  let processor_composition = compositions.last_mut().unwrap();
  processor_composition.inject_container_name(handles.remove(0), "NETWORK_RPC_HOSTNAME");
  processor_composition.inject_container_name(handles.remove(0), "MESSAGE_QUEUE_RPC");

  (compositions[1].handle(), coord_key, compositions)
}

#[cfg(test)]
mod tests;
