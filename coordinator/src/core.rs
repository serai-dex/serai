/// The coordinator core module contains functionality that is shared across modules.
use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use std::{env, fmt, thread, str::FromStr, io::Write};
use chrono::prelude::*;
use env_logger::fmt::Formatter;
use env_logger::Builder;
use log::info;
use log::{LevelFilter, Record};

// Key Generation
use message_box;
use std::alloc::System;
use zalloc::ZeroizingAlloc;
use group::ff::PrimeField;
#[global_allocator]
static ZALLOC: ZeroizingAlloc<System> = ZeroizingAlloc(System);
use std::str;

// rdkafka
use rdkafka::{
  producer::{BaseRecord, ThreadedProducer},
  consumer::{BaseConsumer, Consumer},
  ClientConfig, Message,
  admin::{AdminClient, TopicReplication, NewTopic, AdminOptions},
  client::DefaultClientContext,
};

// All asynchronous processes follow a pattern to modularly
// create, start, and stop their various underlying components.
// for example, the core module will use this pattern to start the
// logger and any other functionality that is requires interaction across
// 3 or more modules.

/// Core Process Struct
///
/// This struct implements the CoordinatorProcess trait and is
/// responsible for starting, stopping. stopping, and handling
/// kafka consumption for:
/// - Logger -- WIP
/// - Database -- TODO
///
/// `core_config` is the configuration for the core process,
/// which contains configurations for kafka, logging, and
/// core host information.

// Configuration for admin client to check / initialize topics
fn create_config(kafka_config: &KafkaConfig) -> ClientConfig {
  let mut config = ClientConfig::new();
  config.set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port));
  config
}

// Creates admin client used to check / initialize topics
fn create_admin_client(kafka_config: &KafkaConfig) -> AdminClient<DefaultClientContext> {
  create_config(kafka_config).create().expect("admin client creation failed")
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoreProcess {
  core_config: CoreConfig,
  chain_config: ChainConfig,
  kafka_config: KafkaConfig,
}

impl CoreProcess {
  pub fn new(config: CoreConfig, chain_config: ChainConfig, kafka_config: KafkaConfig) -> Self {
    Self { core_config: config, chain_config, kafka_config }
  }

  pub async fn run(self, name: String) {
    start_logger(true, String::from("core"), &self.core_config.log_filter);
    info!("Starting Core Process");

    // Check coordinator pubkey env variable
    initialize_keys(name.clone());

    // Initialize Kafka topics
    initialize_kafka_topics(self.chain_config, self.kafka_config.clone(), name.clone()).await;
  }

  fn stop(self) {
    info!("Stopping Core Process");
  }
}

fn start_logger(log_thread: bool, rust_log: String, log_filter: &String) {
  let output_format = move |formatter: &mut Formatter, record: &Record| {
    let thread_name = if log_thread {
      format!("(t: {}) ", thread::current().name().unwrap_or("unknown"))
    } else {
      "".to_string()
    };

    let local_time: DateTime<Local> = Local::now();
    let time_str = local_time.format("%H:%M:%S%.3f").to_string();
    write!(
      formatter,
      "{} {}{} - {} - {}\n",
      time_str,
      thread_name,
      record.level(),
      record.target(),
      record.args()
    )
  };
  let mut builder = Builder::new();
  if log_filter == "info" {
    builder.format(output_format).filter(None, LevelFilter::Info);
  } else {
    builder.format(output_format).filter(None, LevelFilter::Warn);
  }

  builder.parse_filters(&rust_log);

  builder.init();
}

/// RunMode is Used to determine execution environment
#[derive(Copy, Deserialize)]
#[serde(tag = "type")]
pub enum RunMode {
  Development,
  Test,
  Production,
}

impl fmt::Display for RunMode {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      RunMode::Development => write!(f, "development"),
      RunMode::Test => write!(f, "test"),
      RunMode::Production => write!(f, "production"),
    }
  }
}

impl std::str::FromStr for RunMode {
  type Err = String;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "development" => Ok(RunMode::Development),
      "test" => Ok(RunMode::Test),
      "production" => Ok(RunMode::Production),
      _ => Err(format!("{} is not a valid config option", s)),
    }
  }
}

impl fmt::Debug for RunMode {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      RunMode::Development => write!(f, "development"),
      RunMode::Test => write!(f, "test"),
      RunMode::Production => write!(f, "production"),
    }
  }
}

impl Clone for RunMode {
  fn clone(&self) -> Self {
    match self {
      RunMode::Development => RunMode::Development,
      RunMode::Test => RunMode::Test,
      RunMode::Production => RunMode::Production,
    }
  }
}

#[derive(Copy, Deserialize)]
#[serde(tag = "type")]
pub enum ConfigType {
  Core,
  Chain,
  Health,
  Observer,
  Kafka,
  Network,
}

impl fmt::Display for ConfigType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ConfigType::Core => write!(f, "core"),
      ConfigType::Chain => write!(f, "chains"),
      ConfigType::Health => write!(f, "health"),
      ConfigType::Observer => write!(f, "observer"),
      ConfigType::Kafka => write!(f, "kafka"),
      ConfigType::Network => write!(f, "network"),
    }
  }
}

impl fmt::Debug for ConfigType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ConfigType::Core => write!(f, "core"),
      ConfigType::Chain => write!(f, "chains"),
      ConfigType::Health => write!(f, "health"),
      ConfigType::Observer => write!(f, "observer"),
      ConfigType::Kafka => write!(f, "kafka"),
      ConfigType::Network => write!(f, "network"),
    }
  }
}

impl Clone for ConfigType {
  fn clone(&self) -> Self {
    match self {
      ConfigType::Core => ConfigType::Core,
      ConfigType::Chain => ConfigType::Chain,
      ConfigType::Health => ConfigType::Health,
      ConfigType::Observer => ConfigType::Observer,
      ConfigType::Kafka => ConfigType::Kafka,
      ConfigType::Network => ConfigType::Network,
    }
  }
}

/// Public static function to load the configuration
/// based on the provided ConfigType, RunMode, and path.
/// The returned config will be sanitized for the specified ConfigType.

/// # Arguments
/// * `config_type` - The type of configuration to load
/// * `run_mode` - The run mode to load the configuration for
/// * `path` - The path to the configuration file

/// # Returns
/// * `Result<Config, ConfigError>` - The configuration
///  or an error if the configuration could not be loaded
/// or parsed.

pub fn load_config(run_mode: RunMode, path: &str) -> Result<Config, ConfigError> {
  // Load the configuration file
  let run_mode = env::var("COORDINATOR_MODE").unwrap_or_else(|_| "development".into());

  // if runmode is not set, use the default, else load the config file based on the mode specified

  println!("Loading config for mode: {}", run_mode);

  let config = Config::builder()
    .add_source(File::with_name(&format!("{}/{}", path, run_mode)))
    .build()
    .unwrap();

  Ok(config)
}

#[derive(Clone, Debug, Deserialize)]
#[allow(unused)]
pub struct CoreConfig {
  host: String,
  port: String,
  log_filter: String,
}

impl CoreConfig {
  fn new(config: Config) -> Self {
    let host = config.get_string("host").unwrap();
    let port = config.get_string("port").unwrap();
    let log_filter = config.get_string("log_filter").unwrap();
    Self { host, port, log_filter }
  }
  pub fn get_host(&self) -> String {
    self.host.clone()
  }
  pub fn get_port(&self) -> String {
    self.port.clone()
  }
  pub fn get_log_filter(&self) -> String {
    self.log_filter.clone()
  }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(unused)]
pub struct ChainConfig {
  btc: bool,
  eth: bool,
  xmr: bool,
}

impl ChainConfig {
  fn new(config: Config) -> Self {
    let sri = config.get_bool("chain_sri").unwrap();
    let btc = config.get_bool("chain_btc").unwrap();
    let eth = config.get_bool("chain_eth").unwrap();
    let xmr = config.get_bool("chain_xmr").unwrap();
    Self { btc, eth, xmr }
  }
  pub fn get_btc(&self) -> bool {
    self.btc
  }
  pub fn get_eth(&self) -> bool {
    self.eth
  }
  pub fn get_xmr(&self) -> bool {
    self.xmr
  }
}

#[derive(Clone, Debug, Deserialize)]
#[allow(unused)]
pub struct HealthConfig {}

impl HealthConfig {
  pub fn new() -> Self {
    Self {}
  }
}

#[derive(Clone, Debug, Deserialize)]
#[allow(unused)]
pub struct ObserverConfig {
  pub host_prefix: String,
  pub port: String,
}

impl ObserverConfig {
  pub fn get_host_prefix(&self) -> String {
    self.host_prefix.clone()
  }

  pub fn get_port(&self) -> String {
    self.port.clone()
  }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(unused)]
pub struct KafkaConfig {
  pub host: String,
  pub port: String,
  pub offset_reset: String,
}

impl KafkaConfig {
  fn new(config: Config) -> Self {
    let host = config.get_string("host").unwrap();
    let port = config.get_string("port").unwrap();
    let offset_reset = config.get_string("offset_reset").unwrap();
    Self { host, port, offset_reset }
  }
  pub fn get_host(&self) -> String {
    self.host.clone()
  }
  pub fn get_port(&self) -> String {
    self.port.clone()
  }
  pub fn get_offset_reset(&self) -> String {
    self.offset_reset.clone()
  }
}

#[derive(Clone, Debug, Deserialize)]
#[allow(unused)]
pub struct NetworkConfig {
  pub signers: Vec<config::Value>,
}

impl NetworkConfig {
  fn new(config: Config) -> Self {
    let signers = config.get_array("signers").unwrap();
    Self { signers }
  }
}

#[derive(Clone, Debug, Deserialize)]
#[allow(unused)]
pub struct CoordinatorConfig {
  path: String,
  options: RunMode,
  core: CoreConfig,
  health: HealthConfig,
  observer: ObserverConfig,
  chain: ChainConfig,
  kafka: KafkaConfig,
  network: NetworkConfig,
}

impl CoordinatorConfig {
  // Creates a new config based on the set environment
  pub fn new(path: String) -> Result<Self, ConfigError> {
    let run_mode = env::var("COORDINATOR_MODE").unwrap_or_else(|_| "development".into());

    let s = load_config(RunMode::from_str(&run_mode).unwrap(), &path)?;
    // Convert the config into enum for use.
    let mode = RunMode::from_str(&run_mode).unwrap_or(RunMode::Development);

    // switch based on mode to build config
    // TODO: improve mapping syntax
    let config = CoordinatorConfig {
      path: String::from("./config/"),
      options: mode.clone(),
      core: CoreConfig {
        port: s.get_string("core.port").unwrap(),
        host: s.get_string("core.host").unwrap(),
        log_filter: s.get_string("core.log_filter").unwrap(),
      },
      health: HealthConfig {},
      observer: ObserverConfig {
        host_prefix: s.get_string("observer.host_prefix").unwrap(),
        port: s.get_string("observer.port").unwrap(),
      },
      chain: ChainConfig {
        btc: s.get_bool("chains.btc").unwrap(),
        eth: s.get_bool("chains.eth").unwrap(),
        xmr: s.get_bool("chains.xmr").unwrap(),
      },
      kafka: KafkaConfig {
        host: s.get_string("kafka.host").unwrap(),
        port: s.get_string("kafka.port").unwrap(),
        offset_reset: s.get_string("kafka.offset_reset").unwrap(),
      },
      network: NetworkConfig { signers: s.get_array("network.signers").unwrap() },
    };

    match mode {
      RunMode::Development => {
        // Set development specific config
        info!("Development config loaded");
        Ok(config)
      }
      RunMode::Test => {
        // Set test specific config
        info!("Test config loaded");
        Ok(config)
      }
      RunMode::Production => {
        // Set production specific config
        info!("Production config loaded");
        Ok(config)
      }
    }
  }

  // get the config path
  pub fn get_path(&self) -> String {
    self.path.clone()
  }
  // get the config options
  pub fn get_options(&self) -> RunMode {
    self.options.clone()
  }
  // get the core config
  pub fn get_core(&self) -> CoreConfig {
    self.core.clone()
  }
  // get the health config
  pub fn get_health(&self) -> HealthConfig {
    self.health.clone()
  }
  // get the observer config
  pub fn get_observer(&self) -> ObserverConfig {
    self.observer.clone()
  }
  // get the chain config
  pub fn get_chain(&self) -> ChainConfig {
    self.chain.clone()
  }
  // get the kafka config
  pub fn get_kafka(&self) -> KafkaConfig {
    self.kafka.clone()
  }
  // get the network config
  pub fn get_network(&self) -> NetworkConfig {
    self.network.clone()
  }
}

// Generates Private / Public key pair
pub fn initialize_keys(name: String) {
  // Checks if coordinator keys are set
  let coord_priv_check = env::var("COORD_PRIV");
  if coord_priv_check.is_err() {
    info!("Generating New Keys");
    // Generates new private / public key
    let (private, public) = message_box::key_gen();
    let private_bytes = unsafe { private.inner().to_repr() };

    let env_priv_key = format!("COORD_{}_PRIV", name.to_uppercase());
    let env_pub_key = format!("COORD_{}_PUB", name.to_uppercase());

    // Sets private / public key to environment variables
    env::set_var(env_priv_key, hex::encode(&private_bytes.as_ref()));
    env::set_var(env_pub_key, hex::encode(&public.to_bytes()));
  } else {
    info!("Keys Found");
  }
}

async fn initialize_kafka_topics(
  chain_config: ChainConfig,
  kafka_config: KafkaConfig,
  name: String,
) {
  let j = serde_json::to_string(&chain_config).unwrap();
  let topic_ref: HashMap<String, bool> = serde_json::from_str(&j).unwrap();

  let admin_client = create_admin_client(&kafka_config);
  let opts = AdminOptions::new().operation_timeout(Some(Duration::from_secs(1)));

  let serai_topic_name = format!("{}_node", &name);

  let initialized_topic = NewTopic {
    name: &serai_topic_name,
    num_partitions: 2,
    replication: TopicReplication::Fixed(1),
    config: Vec::new(),
  };

  admin_client.create_topics(&[initialized_topic], &opts).await.expect("topic creation failed");

  // Loop through each coin & initialize each kakfa topic
  for (_key, _value) in topic_ref.into_iter() {
    let mut topic: String = "".to_string();
    topic.push_str(&name);
    let topic_ref = &mut String::from(&_key).to_lowercase();
    topic.push_str("_processor_");
    topic.push_str(topic_ref);

    let initialized_topic = NewTopic {
      name: &topic,
      num_partitions: 2,
      replication: TopicReplication::Fixed(1),
      config: Vec::new(),
    };

    admin_client.create_topics(&[initialized_topic], &opts).await.expect("topic creation failed");
  }
}
