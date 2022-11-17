/// The coordinator module contains functionality that is shared across modules.
use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize};
use std::{env, fmt, thread, str::FromStr, io::Write};
use chrono::prelude::*;
use env_logger::fmt::Formatter;
use env_logger::Builder;
use log::info;
use log::{LevelFilter, Record};

// Key Generation
use message_box;
use std::alloc::System;
use zeroize::Zeroize;
use zalloc::ZeroizingAlloc;
use group::ff::PrimeField;
#[global_allocator]
static ZALLOC: ZeroizingAlloc<System> = ZeroizingAlloc(System);



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
#[derive( Clone, Debug, Deserialize)]
pub struct CoreProcess {
  core_config: CoreConfig,
}

impl CoreProcess {
  pub fn new(config: CoordinatorConfig) -> Self {
    println!("New Core Process");
    let core_config = config.get_core();
    Self { core_config: core_config }
  }

  pub fn start(self) {
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
}

impl fmt::Display for ConfigType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ConfigType::Core => write!(f, "core"),
      ConfigType::Chain => write!(f, "chains"),
      ConfigType::Health => write!(f, "health"),
      ConfigType::Observer => write!(f, "observer"),
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
    .build().unwrap();
  
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

// TODO: change to a struct with a builder pattern
#[derive(Clone, Debug, Deserialize)]
#[allow(unused)]
struct ChainConfig {
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

#[derive(Clone, Debug, Deserialize)]
#[allow(unused)]
pub struct CoordinatorConfig {
  path: String,
  options: RunMode,
  core: CoreConfig,
  health: HealthConfig,
  observer: ObserverConfig,
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
    };

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
}

// Generates Private / Public key pair
pub fn instantiate_keys(){
  // A_PRIV and B_PRIV are dynamic testing keys for kafka
  let a_priv_check = env::var("A_PRIV");
  if (a_priv_check.is_err()) {
    const A_PRIV: &'static str = "543600cc54df140d0186f604b3a606cb3d2103327106703e80c183a481cf2a09";
    env::set_var("A_PRIV", A_PRIV);
  }

  let a_pub_check = env::var("A_PUB");
  if (a_pub_check.is_err()) {
    const A_PUB: &'static str = "ecb27e79e414f51ed0b1b14502611247a99fc81a58ff78604cb7789aaceebf02";
    env::set_var("A_PUB", A_PUB);
  }

  let b_priv_check = env::var("B_PRIV");
  if (b_priv_check.is_err()) {
    const B_PRIV: &'static str = "db97aa4549842b113bf502ec47905a31c0a97837dcaa8e59ed0f12ee6b33a60c";
    env::set_var("B_PRIV", B_PRIV);
  }

  let b_pub_check = env::var("B_PUB");
  if (b_pub_check.is_err()) {
    const B_PUB: &'static str = "bc5e598f9337bb98b0e58b4b62fd99f2ccefbc5d4befbfe1e16dcbebab44115c";
    env::set_var("B_PUB", B_PUB);
  }

  // Kafka Flow
  
  // Initializes BTC Message Box credentials
  let btc_box_priv_check = env::var("BTC_BOX_PRIV");
  if (btc_box_priv_check.is_err()) {
    const BTC_BOX_PRIV: &'static str = "20e16728973325729556218324ae6aa4d45c165048e5ea088e625ca5ffdb280c";
    env::set_var("BTC_BOX_PRIV", BTC_BOX_PRIV);
  }

  let btc_pub_check = env::var("BTC_BOX_PUB");
  if (btc_pub_check.is_err()) {
    const BTC_BOX_PUB: &'static str = "2a9881c66487861603a3049f1a2fa3b1587dba4ac67edbbbd860a003c28f561c";
    env::set_var("BTC_BOX_PUB", BTC_BOX_PUB);
  }

  // Initializes ETH Message Box credentials
  let eth_priv_check = env::var("ETH_BOX_PRIV");
  if (eth_priv_check.is_err()) {
    const ETH_BOX_PRIV: &'static str = "317bca0126576608a21e6deb0a93fae0b0dd594531eba7f39bc9a5df678cc209";
    env::set_var("ETH_BOX_PRIV", ETH_BOX_PRIV);
  }

  let eth_pub_check = env::var("ETH_BOX_PUB");
  if (eth_pub_check.is_err()) {
    const ETH_BOX_PUB: &'static str = "b81a54e422a9c3291024f58c435c7a8237126a796630f92f0b0c260667443231";
    env::set_var("ETH_BOX_PUB", ETH_BOX_PUB);
  }

  // Initializes XMR Message Box credentials
  let xmr_priv_check = env::var("XMR_BOX_PRIV");
  if (xmr_priv_check.is_err()) {
    const XMR_BOX_PRIV: &'static str = "3c0a24ee04b8803d73eb686e7cadf6f266468023e656fdf097d4706e6276f30b";
    env::set_var("XMR_BOX_PRIV", XMR_BOX_PRIV);
  }

  let xmr_pub_check = env::var("XMR_BOX_PUB");
  if (xmr_pub_check.is_err()) {
    const XMR_BOX_PUB: &'static str = "4e4fd2169ff07db08c65fedf83097481cdc5c4f5de27c2a37f1a8d82da6ad447";
    env::set_var("XMR_BOX_PUB", XMR_BOX_PUB);
  }

  // Initializes Node Message Box credentials
  let node_priv_check = env::var("NODE_BOX_PRIV");
  if (node_priv_check.is_err()) {
    const NODE_BOX_PRIV: &'static str = "8fa83f048c85fd920465f89ab4f71bd5b1c4484ab6a9e605ec996afc97f30201";
    env::set_var("NODE_BOX_PRIV", NODE_BOX_PRIV);
  }

  let node_pub_check = env::var("NODE_BOX_PUB");
  if (node_pub_check.is_err()) {
    const NODE_BOX_PUB: &'static str = "1a94987e207fa960ce698c880b0ad23359562646db6c4b703650616fa03b1f0a";
    env::set_var("NODE_BOX_PUB", NODE_BOX_PUB);
  }

  // Initializes Coordinator Message Box credentials
  let coord_priv_check = env::var("COORD_BOX_PRIV");
  if (coord_priv_check.is_err()) {
    const COORD_BOX_PRIV: &'static str = "7d9cff45c6678111c998fde637bf19f958ff760e37fe1c238b333feb4ff9640f";
    env::set_var("COORD_BOX_PRIV", COORD_BOX_PRIV);
  }

  let coord_pub_check = env::var("COORD_BOX_PUB");
  if (coord_pub_check.is_err()) {
    const COORD_BOX_PUB: &'static str = "3e2950d74aca927a675d16db9f625544335498aec2ce3b9b64bc30033558ee05";
    env::set_var("COORD_BOX_PUB", COORD_BOX_PUB);
  }

  // Initializes Substrate Message Box credentials
  let substate_priv_check = env::var("SUBSTRATE_BOX_PRIV");
  if (substate_priv_check.is_err()) {
    const SUBSTRATE_BOX_PRIV: &'static str = "62f25c3cfbd2f908df77a21ac3041d02601f58bf3805070bb2da4929616f0b04";
    env::set_var("SUBSTRATE_BOX_PRIV", SUBSTRATE_BOX_PRIV);
  }

  let substrate_pub_check = env::var("SUBSTRATE_BOX_PUB");
  if (substrate_pub_check.is_err()) {
    const SUBSTRATE_BOX_PUB: &'static str = "8ead618c644f835b403523696423820d59f57f5df290954c8a02ca0e86d0730f";
    env::set_var("SUBSTRATE_BOX_PUB", SUBSTRATE_BOX_PUB);
  }

  // Checks if coordinator test keys are set
  let coord_priv_check = env::var("COORD_PRIV");
  if (coord_priv_check.is_err()) {
    //println!("Generating new coordinator keys");
    let (private, public) = message_box::key_gen();
    let mut private_bytes = unsafe { private.inner().to_repr() };
    //println!("Private: {}", hex::encode(private_bytes.as_ref()));
    private_bytes.zeroize();
    //println!("Public: {}", hex::encode(public.to_bytes()));

    env::set_var("COORD_PRIV", hex::encode(private_bytes.as_ref()));
    env::set_var("COORD_PUB",  hex::encode(public.to_bytes()));
  }
}