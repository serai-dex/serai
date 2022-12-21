/// The processor core module contains functionality that is shared across modules.
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

#[derive(Clone, Debug, Deserialize)]
pub struct CoreProcess {
  core_config: CoreConfig,
  coin: String,
}

impl CoreProcess {
  pub fn new(core_config: CoreConfig, coin: String) -> Self {
    Self { core_config: core_config, coin: coin }
  }

  pub fn run(self) {
    start_logger(true, String::from("core"), &self.core_config.log_filter);
    info!("Starting Core Process");

    // Check coordinator pubkey env variable
    initialize_keys(&self.coin);
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
pub struct ProcessorConfig {
  coin: String,
  path: String,
  options: RunMode,
  core: CoreConfig,
  health: HealthConfig,
  observer: ObserverConfig,
  kafka: KafkaConfig,
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

impl ProcessorConfig {
  // Creates a new config based on the set environment
  pub fn new(path: String, coin: String) -> Result<Self, ConfigError> {
    let run_mode = env::var("PROCESSOR_MODE").unwrap_or_else(|_| "development".into());

    let s = load_config(RunMode::from_str(&run_mode).unwrap(), &path)?;

    // Convert the config into enum for use.
    let mode = RunMode::from_str(&run_mode).unwrap_or(RunMode::Development);

    // switch based on mode to build config
    let config = ProcessorConfig {
      coin: coin,
      path: String::from("./config/"),
      options: mode.clone(),
      core: CoreConfig {
        port: s.get_string("core.port").unwrap(),
        host: s.get_string("core.host").unwrap(),
        log_filter: s.get_string("core.log_filter").unwrap(),
      },
      health: HealthConfig {},
      observer: ObserverConfig {
        host: String::from("localhost"),
        port: String::from("5050"),
        poll_interval: 1,
      },
      kafka: KafkaConfig {
        host: s.get_string("kafka.host").unwrap(),
        port: s.get_string("kafka.port").unwrap(),
        offset_reset: s.get_string("kafka.offset_reset").unwrap(),
      },
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
  pub fn get_coin(&self) -> String {
    self.coin.clone()
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
  // get the kafka config
  pub fn get_kafka(&self) -> KafkaConfig {
    self.kafka.clone()
  }
}

// Accepts startup argument specifying which coin package to start
pub fn initialize_coin(coin: &str) {
  info!("Received Coin Request: {}", coin);

  match coin {
    "btc" => {}
    "eth" => {}
    "xmr" => {}
    "sri" => {}
    _ => info!("coin unavailable {}", coin),
  }
}

// Generates Private / Public key pair
pub fn initialize_keys(coin: &String) {
  let mut env_privkey = String::from(coin).to_uppercase();
  env_privkey.push_str("_PRIV");

  // Checks if coin keys are set
  let priv_check = env::var(&env_privkey.to_string());
  if priv_check.is_err() {
    // Generates new private / public key
    let (privkey, pubkey) = message_box::key_gen();
    let mut privkey_bytes = unsafe { privkey.inner().to_repr() };
    // Sets private / public key to environment variables
    env::set_var(&env_privkey, hex::encode(&privkey_bytes.as_ref()));

    let mut env_pubkey = String::from(coin).to_uppercase();
    env_pubkey.push_str("_PUB");
    env::set_var(&env_pubkey, hex::encode(&pubkey.to_bytes()));
  }
}
