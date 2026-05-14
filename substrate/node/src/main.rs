#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]
#![expect(clippy::result_large_err)]

use core::{str::FromStr as _, time::Duration};
use std::path::PathBuf;

use zeroize::Zeroizing;

use sp_core::{Pair as _, sr25519::Pair};

use serai_abi::primitives::address::SeraiAddress;

use sc_service::{config::*, Role, DatabaseSource, BlocksPruning, PruningMode, Configuration, Task};

use serai_env::Environment;

use clap::Parser;

mod keystore;
use keystore::Keystore;

mod chain_spec;
mod service;
use service::FullClient;

mod rpc;

mod exit;

#[derive(Clone)]
enum Network {
  Solo,
  Local,
}

impl Network {
  fn as_str(&self) -> &'static str {
    match self {
      Network::Solo => "solo",
      Network::Local => "local",
    }
  }

  fn public(&self) -> bool {
    !matches!(self, Network::Solo | Network::Local)
  }
}

impl core::fmt::Display for Network {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

impl clap::ValueEnum for Network {
  fn value_variants<'a>() -> &'a [Self] {
    &[Self::Solo, Self::Local]
  }
  fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
    Some(clap::builder::PossibleValue::new(self.as_str()))
  }
}

#[derive(Clone)]
enum Database {
  RocksDb,
  ParityDb,
}

impl Database {
  fn as_str(&self) -> &'static str {
    match self {
      Database::RocksDb => "rocksdb",
      Database::ParityDb => "parity-db",
    }
  }
}

impl core::fmt::Display for Database {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

impl clap::ValueEnum for Database {
  fn value_variants<'a>() -> &'a [Self] {
    &[Self::RocksDb, Self::ParityDb]
  }
  fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
    Some(clap::builder::PossibleValue::new(self.as_str()))
  }
}

fn node_key(keystore: Option<&Keystore>) -> NodeKeyConfig {
  let mut seed = match keystore {
    /*
      If we have a keystore, set our `node_key` to be deterministic to it. This avoids having to
      actively manage multiple key materials for the node's operation.

      Because the auxiliary key is defined over Ristretto, yet the P2P network uses Ed25519, we
      are unable to use the existing derivation scheme (though one can technically define a
      mapping between the two groups). As we do not require _public_ derivation of node keys,
      though that is a requirement for subkeys, we simply use a domain-separated hash of a
      derived private key to generate the necessary key material.
    */
    Some(keystore) => {
      let node_key_entropy = keystore.pair(sp_core::crypto::KeyTypeId(*b"p2ed"));
      let node_key_entropy = Zeroizing::new(node_key_entropy.to_raw_vec());
      /*
        This effects a hardened derivation, which may or may not be necessary. Specifically,
        the sr25519 VRF is premised on the computation of Diffie-Hellmans, and transports
        frequently derive a symmetric encryption key from a Diffie-Hellman. If the P2P protocol
        grants the adversary a DH oracle (they can provide an arbitrary point and receive the
        DH for a validator's key and that point, such as if they open a transport, claim an
        arbitrary point is in fact their own key (causing the validator to perform the DH), and
        then somehow learn the symmetric key from there), then usage of a P2P key with a known
        relation to the key used with BABE may break the security of BABE (due to granting the
        adversary the ability to learn random numbers before everyone else).

        Similar concerns exist any time we wish to provide keys of known relation for usage in
        arbitrary protocols. The usage within the runtime itself is only safe as all the keys
        are solely used for signing (as fine to compose) except for the singular usage for the
        BABE VRF (which is fine to compose with signing). This has to be kept in mind when we
        now start using keys, derived in any manner, with other protocols such as the P2P layer
        however.
      */
      Zeroizing::new(sp_core::blake2_256(&node_key_entropy))
    }

    // If we do not have a keystore, generate a seed now
    // TODO: `Secret::File` with `net_config_path`
    None => {
      use rand_core::{RngCore as _, OsRng};
      let mut seed = Zeroizing::new([0; 32]);
      OsRng.fill_bytes(seed.as_mut());
      seed
    }
  };

  // Perform a rejection sample such that this will keep sampling keys until it finds one
  loop {
    use sc_network::config::{Secret, ed25519::SecretKey};
    let Ok(node_key) = SecretKey::try_from_bytes(seed.clone()) else {
      *seed = sp_core::blake2_256(seed.as_slice());
      continue;
    };
    return NodeKeyConfig::Ed25519(Secret::Input(node_key));
  }
}

fn network_configuration(
  net_config_path: PathBuf,
  public_network: bool,
  keystore: Option<&Keystore>,
) -> NetworkConfiguration {
  let default = NetworkConfiguration::new(
    "",
    "",
    {
      use sc_network::config::{Secret, ed25519::SecretKey};
      NodeKeyConfig::Ed25519(Secret::Input(SecretKey::try_from_bytes([0; 32]).unwrap()))
    },
    None,
  );

  NetworkConfiguration {
    // TODO: Decide if we want to automatically generate a name or defer to the node's key
    // Potentially, derive a name from the key?
    node_name: "Serai".to_owned(),
    /*
      This allows detecting the features a node should have over the wire protocol, without
      identifying if the node has patched to the latest update or not (to a passive observer).
    */
    client_version: format!(
      "{}.{}",
      env!("CARGO_PKG_VERSION_MAJOR"),
      env!("CARGO_PKG_VERSION_MINOR")
    ),

    net_config_path: Some(net_config_path),
    node_key: node_key(keystore),

    // TODO: Decide, and define a constant for, our port number (and accept CLI overrides)
    listen_addresses: vec![
      "/ip4/0.0.0.0/tcp/30333".parse().unwrap(),
      "/ip6/::/tcp/30333".parse().unwrap(),
    ],
    // TODO: Allow specification over the CLI
    public_addresses: vec![],

    // TODO: Take in from the chain spec
    boot_nodes: vec![],

    network_backend: sc_network::config::NetworkBackendType::Libp2p,
    transport: TransportConfig::Normal {
      enable_mdns: !public_network,
      allow_private_ip: !public_network,
    },
    allow_non_globals_in_dht: !public_network,

    sync_mode: SyncMode::Full,
    // This is to effectively disable warp sync
    min_peers_to_start_warp_sync: Some(usize::MAX),

    enable_dht_random_walk: true,
    kademlia_disjoint_query_paths: true,
    kademlia_replication_factor: default.kademlia_replication_factor,

    default_peers_set: default.default_peers_set,
    default_peers_set_num_full: default.default_peers_set_num_full,
    idle_connection_timeout: default.idle_connection_timeout,
    max_parallel_downloads: default.max_parallel_downloads,
    max_blocks_per_request: default.max_blocks_per_request,
  }
}

#[derive(Parser)]
struct Cli {
  #[arg(long)]
  data_dir: Option<String>,
  #[arg(long)]
  network: Network,
  #[arg(long, default_value_t = Database::RocksDb)]
  database: Database,
  #[arg(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
  validator: bool,
  #[arg(long)]
  identity: Option<String>,
}

fn main() {
  let (base_path, network, database, role, dev_key_seed) = {
    let Cli { data_dir, network, database, validator, identity } = Cli::parse();

    let base_path = if let Some(data_dir) = data_dir {
      PathBuf::from(data_dir).into()
    } else if matches!(network, Network::Solo) {
      sc_service::config::BasePath::new_temp_dir()
        .expect("couldn't create temp directory for solo network")
    } else {
      dirs::data_dir()
        .expect("`data-dir` argument not set and couldn't locate the user's data directory")
        .join("serai")
        .into()
    };

    let dev_key_seed =
      identity.or(matches!(network, Network::Solo).then(|| "alice".to_owned())).map(|identity| {
        assert!(!network.public(), "identities may only be used in test environments");

        let identity = identity.to_lowercase();
        let dev_key_seed = (match identity.as_str() {
          "alice" => sp_keyring::sr25519::Keyring::Alice,
          "bob" => sp_keyring::sr25519::Keyring::Bob,
          "claire" => sp_keyring::sr25519::Keyring::Charlie,
          "dave" => sp_keyring::sr25519::Keyring::Dave,
          _ => panic!(r#"unrecognized identity: "{identity}""#),
        })
        .to_seed();

        if matches!(network, Network::Solo) {
          assert_eq!(
            identity, "alice",
            r#"only "alice" is allowed as an identity for a solo network"#
          );
        }

        dev_key_seed
      });

    let role = if validator || dev_key_seed.is_some() { Role::Authority } else { Role::Full };

    (base_path, network, database, role, dev_key_seed)
  };
  let data_path = base_path.path().join(network.as_str());

  let runtime = tokio::runtime::Builder::new_multi_thread()
    .on_thread_start(|| {
      sc_utils::metrics::TOKIO_THREADS_ALIVE.inc();
      sc_utils::metrics::TOKIO_THREADS_TOTAL.inc();
    })
    .on_thread_stop(|| sc_utils::metrics::TOKIO_THREADS_ALIVE.dec())
    .enable_all()
    .build()
    .unwrap();

  // Load our bespoke definition of a keystore
  let mut env = None;
  let validator_identity_and_keystore: Option<(SeraiAddress, Keystore)> = if let Some(seed) =
    &dev_key_seed
  {
    let pair = Pair::from_string(seed, None).expect("dev key had invalid seed");
    let validator_identity = chain_spec::validator_identity_for_dev_seed(seed);
    Some((validator_identity, Keystore::from(pair)))
  } else if role.is_authority() {
    let inner_env = runtime
      .block_on(tokio::time::timeout(Duration::from_mins(5), Environment::from_secret_store()))
      .expect("`--validator`, with no dev key, yet couldn't receive secrets from the Secret Store");
    let (validator_identity, keystore) = Keystore::from_env(&inner_env)
      .expect("`--validator`, with no dev key, and no environment key");
    env = Some(inner_env);
    Some((validator_identity, keystore))
  } else {
    None
  };
  if role.is_authority() {
    assert!(validator_identity_and_keystore.is_some(), "`--validator` yet no keystore provided");
  }

  let network_config_path = data_path.join("net");
  let database_path = data_path.join("db").join(database.as_str());
  let database = match database {
    Database::RocksDb => DatabaseSource::RocksDb {
      path: database_path,
      // `cache_size` is denoted in MiB
      cache_size: 256,
    },
    Database::ParityDb => DatabaseSource::ParityDb { path: database_path },
  };

  // TODO: Allow setting these parameters over the CLI
  let mut blocks_pruning = None;
  let mut state_pruning = None;
  if role.is_authority() {
    let validator_blocks_pruning = Some(BlocksPruning::KeepFinalized);
    // TODO: https://github.com/serai-dex/serai/issues/696
    let validator_state_pruning = Some(PruningMode::ArchiveCanonical);
    blocks_pruning = blocks_pruning.or(validator_blocks_pruning);
    state_pruning = state_pruning.or(validator_state_pruning.clone());
    assert_eq!(
      blocks_pruning, validator_blocks_pruning,
      "blocks were not configured to be archived, which is required when running a validator"
    );
    assert_eq!(
      state_pruning, validator_state_pruning,
      "state was not configured to be archived, which is required when running a validator"
    );
  }

  // TODO: Allow setting this over the CLI
  let rpc_port = 9944;

  let config = Configuration {
    tokio_handle: runtime.handle().clone(),

    impl_name: "Serai".to_owned(),
    impl_version: env!("CARGO_PKG_VERSION").to_owned(),

    role,
    keystore: KeystoreConfig::InMemory,
    dev_key_seed: None,

    transaction_pool: TransactionPoolOptions::default(),
    network: network_configuration(
      network_config_path,
      network.public(),
      validator_identity_and_keystore.as_ref().map(|(_identity, keystore)| keystore),
    ),
    announce_block: true,

    base_path,
    data_path,
    database,
    trie_cache_maximum_size: None,
    warm_up_trie_cache: None,
    blocks_pruning: blocks_pruning.unwrap_or(BlocksPruning::KeepFinalized),
    state_pruning: Some(state_pruning.unwrap_or(PruningMode::ArchiveCanonical)),

    executor: ExecutorConfiguration {
      wasm_method: WasmExecutionMethod::Compiled {
        instantiation_strategy: WasmtimeInstantiationStrategy::PoolingCopyOnWrite,
      },
      max_runtime_instances: ExecutorConfiguration::default().max_runtime_instances,
      default_heap_pages: None,
      runtime_cache_size: 2,
    },
    chain_spec: Box::new(match network {
      Network::Solo => chain_spec::solo_config(env.as_ref()),
      Network::Local => chain_spec::local_config(env.as_ref()),
    }),
    wasm_runtime_overrides: None,

    offchain_worker: OffchainWorkerConfig { enabled: false, indexing_enabled: false },

    force_authoring: matches!(network, Network::Solo),
    disable_grandpa: false,

    /*
      TODO: This configuration is only safe so long as the node is only reachable by trusted
      entities. It is NOT fit for public consumption and MUST be proxied by an external solution
      which successfully, and comprehensively, provides rate limiting.
    */
    rpc: RpcConfiguration {
      addr: Some({
        let rpc_endpoint = |listen_addr| RpcEndpoint {
          listen_addr: core::net::SocketAddr::from_str(&format!("{listen_addr}:{rpc_port}"))
            .unwrap(),
          batch_config: RpcBatchRequestConfig::Unlimited,
          max_connections: u32::MAX,
          max_payload_in_mb: u32::MAX,
          max_payload_out_mb: u32::MAX,
          max_subscriptions_per_connection: u32::MAX,
          max_buffer_capacity_per_connection: u32::MAX,
          rate_limit: None,
          rate_limit_trust_proxy_headers: true,
          rate_limit_whitelisted_ips: vec![],
          cors: None,
          rpc_methods: RpcMethods::Unsafe,
          is_optional: true,
          retry_random_port: false,
        };
        vec![rpc_endpoint("0.0.0.0"), rpc_endpoint("[::]")]
      }),
      max_connections: u32::MAX,
      cors: None,
      methods: sc_service::RpcMethods::Unsafe,
      max_request_size: u32::MAX,
      max_response_size: u32::MAX,
      // These IDs are alphanumeric, but even if hex, 32 characters would offer 128 bits of entropy
      // TODO: Some(Box::new(sc_service::RandomStringSubscriptionId::new(32)))
      // The following will be unwrapped to something approximate, as a default
      id_provider: None,
      max_subs_per_conn: u32::MAX,
      port: rpc_port,
      message_buffer_capacity: u32::MAX,
      batch_config: RpcBatchRequestConfig::Unlimited,
      rate_limit: None,
      rate_limit_whitelisted_ips: vec![],
      rate_limit_trust_proxy_headers: true,
      request_logger_limit: u32::MAX,
    },

    // This is the only entry of `enum TracingReceiver`
    tracing_receiver: sc_service::TracingReceiver::Log,
    // TODO: Expose over the CLI
    tracing_targets: None,
    // TODO: Expose over the CLI
    prometheus_config: None,
    // TODO: Expose over the CLI
    telemetry_endpoints: None,
  };

  {
    let log_filters = String::new();
    let mut logger = sc_tracing::logging::LoggerBuilder::new(log_filters);
    if let Some(targets) = config.tracing_targets.clone() {
      logger.with_profiling(config.tracing_receiver.clone(), targets);
    }
    logger.with_colors(std::io::IsTerminal::is_terminal(&std::io::stdout()));
    logger.init().expect("failed to initialize logger");
  }

  let mut task_manager = runtime.block_on(async move {
    assert_eq!(
      validator_identity_and_keystore.is_some(),
      config.role.is_authority(),
      "unrecognized keystore to operate a validator with"
    );

    service::new_full(validator_identity_and_keystore, config).expect("failed to spawn service")
  });

  // Run tasks until a signal to exit is received
  runtime.block_on(async {
    let task_manager = futures_util::FutureExt::fuse(task_manager.future());
    let exit = exit::Exit::new();
    tokio::select! {
      _ = task_manager => {},
      () = exit => {}
    }
  });

  // Shut down
  let task_registry = task_manager.into_task_registry();
  const SHUTDOWN_TIMEOUT: Duration = Duration::from_mins(1);
  sp_tracing::info!("Shutting down (with {}s timeout)", SHUTDOWN_TIMEOUT.as_secs());
  runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);

  // Check all tasks successfully terminated within the timeout given
  assert_eq!(
    task_registry
      .running_tasks()
      .into_iter()
      .map(|(Task { name, group }, count)| (name, group, count))
      .collect::<Vec<_>>(),
    vec![],
    "not all tasks finished within the timeout"
  );
}
