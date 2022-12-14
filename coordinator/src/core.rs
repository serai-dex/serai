/// The coordinator core module contains functionality that is shared across modules.
use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
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
#[derive(Clone, Debug, Deserialize)]
pub struct CoreProcess {
  core_config: CoreConfig,
}

impl CoreProcess {
  pub fn new(config: CoordinatorConfig) -> Self {
    println!("New Core Process");
    let core_config = config.get_core();
    Self { core_config: core_config }
  }

  pub fn run(self) {
    println!("Starting Core Process");
    start_logger(true, String::from("core"));
  }

  fn stop(self) {
    println!("Stopping Core Process");
  }
}

fn start_logger(log_thread: bool, rust_log: String) {
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
  builder.format(output_format).filter(None, LevelFilter::Info);

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
}

impl fmt::Display for ConfigType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ConfigType::Core => write!(f, "core"),
      ConfigType::Chain => write!(f, "chains"),
      ConfigType::Health => write!(f, "health"),
      ConfigType::Observer => write!(f, "observer"),
      ConfigType::Kafka => write!(f, "kafka"),
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
// TODO: We could draw from a single cached instace of the config
// and return a copy of the config for each config type. Does it matter?

pub fn load_config(
  config_type: ConfigType,
  run_mode: RunMode,
  path: &str,
) -> Result<Config, ConfigError> {
  // Load the configuration file
  let run_mode = env::var("COORDINATOR_MODE").unwrap_or_else(|_| "development".into());

  let config = Config::builder()
    // Start off by merging in the "default" configuration file
    .add_source(File::with_name(&format!("{}/default", path)))
    // Add in the current environment file
    // Default to 'development' env
    // Note that this file is _optional_
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
}

impl CoreConfig {
  fn new(config: Config) -> Self {
    let host = config.get_string("host").unwrap();
    let port = config.get_string("port").unwrap();
    Self { host, port }
  }
  pub fn get_host(&self) -> String {
    self.host.clone()
  }
  pub fn get_port(&self) -> String {
    self.port.clone()
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
struct HealthConfig {}

impl HealthConfig {
  pub fn new() -> Self {
    Self {}
  }
}

#[derive(Clone, Debug, Deserialize)]
#[allow(unused)]
struct ObserverConfig {
  host: String,
  port: String,
  poll_interval: u16,
}

impl ObserverConfig {
  pub fn get_host(&self) -> String {
    self.host.clone()
  }

  pub fn get_port(&self) -> String {
    self.port.clone()
  }

  pub fn get_poll_interval(&self) -> u16 {
    self.poll_interval
  }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(unused)]
pub struct KafkaConfig {
  pub server: String,
}

impl KafkaConfig {
  fn new(config: Config) -> Self {
    let server = config.get_string("server").unwrap();
    Self { server }
  }
  pub fn get_server(&self) -> String {
    self.server.clone()
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
}

impl CoordinatorConfig {
  // Creates a new config based on the set environment
  pub fn new(path: String) -> Result<Self, ConfigError> {
    let run_mode = env::var("COORDINATOR_MODE").unwrap_or_else(|_| "development".into());

    let s = Config::builder()
      // Start off by merging in the "default" configuration file
      .add_source(File::with_name(&format!("{}/default", path)))
      // Add in the current environment file
      // Default to 'development' env
      // Note that this file is _optional_
      .add_source(File::with_name(&format!("{}/{}", path, run_mode)))
      .build()?;

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
      },
      health: HealthConfig {},
      observer: ObserverConfig {
        host: String::from("localhost"),
        port: String::from("5050"),
        poll_interval: 1,
      },
      chain: ChainConfig {
        btc: s.get_bool("chains.btc").unwrap(),
        eth: s.get_bool("chains.eth").unwrap(),
        xmr: s.get_bool("chains.xmr").unwrap(),
      },
      kafka: KafkaConfig {
        server: s.get_string("kafka.server").unwrap(),
      },
    };

    // Check coordinator pubkey env variable
    initialize_keys();

    match mode {
      RunMode::Development => {
        // Set development specific config
        println!("Development config loaded");
        Ok(config)
      }
      RunMode::Test => {
        // Set test specific config
        println!("Test config loaded");
        Ok(config)
      }
      RunMode::Production => {
        // Set production specific config
        println!("Production config loaded");
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
}

// Generates Private / Public key pair
pub fn initialize_keys() {
  // Checks if coordinator keys are set
  let coord_priv_check = env::var("COORD_PRIV");
  if coord_priv_check.is_err() {
    println!("Generating New Keys");
    // Generates new private / public key
    let (private, public) = message_box::key_gen();
    let private_bytes = unsafe { private.inner().to_repr() };
    // Sets private / public key to environment variables
    env::set_var("COORD_PRIV", hex::encode(&private_bytes.as_ref()));
    env::set_var("COORD_PUB", hex::encode(&public.to_bytes()));
  } else {
    println!("Keys Found");
  }
}
