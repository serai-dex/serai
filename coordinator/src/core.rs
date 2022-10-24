// The coordinator module contains general configurations and types that are used
// by the coordinator and held modules.
  use config::{Config, ConfigError, Environment, File};
  use serde::{Deserialize};
  use std::{env, fmt, str::FromStr};

  trait CoordinatorProcess {
    fn new() -> Self;
    fn start(&mut self);
    fn stop(&mut self);
  }

  #[derive(Debug, Deserialize)]
  struct CoreProcess {
    core_config: CoreConfig
  }

  impl CoordinatorProcess for CoreProcess {
    fn new() -> Self {
      Self {
        print("New Core Process")
      }
    }

    fn start(&mut self) {
      println!("Starting Core Process");
    }

    fn stop(&mut self) {
      println!("Stopping Core Process");
    }
  }

  // Used to determine execution environment
  #[derive(Copy, Deserialize)]
  #[serde(tag = "type")]
  pub enum ConfigOption {
    Development,
    Test,
    Production,
  }

  impl fmt::Display for ConfigOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      match self {
        ConfigOption::Development => write!(f, "development"),
        ConfigOption::Test => write!(f, "test"),
        ConfigOption::Production => write!(f, "production"),
      }
    }
  }

  impl std::str::FromStr for ConfigOption {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
      match s {
        "development" => Ok(ConfigOption::Development),
        "test" => Ok(ConfigOption::Test),
        "production" => Ok(ConfigOption::Production),
        _ => Err(format!("{} is not a valid config option", s)),
      }
    }
  }

  impl fmt::Debug for ConfigOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      match self {
        ConfigOption::Development => write!(f, "development"),
        ConfigOption::Test => write!(f, "test"),
        ConfigOption::Production => write!(f, "production"),
      }
    }
  }

  impl Clone for ConfigOption {
    fn clone(&self) -> Self {
      match self {
        ConfigOption::Development => ConfigOption::Development,
        ConfigOption::Test => ConfigOption::Test,
        ConfigOption::Production => ConfigOption::Production,
      }
    }
  }

  #[derive(Debug, Deserialize)]
  #[allow(unused)]
  pub struct CoreConfig {
    host: String,
    port: String,
  }

   impl CoreConfig {
    pub fn get_host(&self) -> String {
      self.host.clone()
    }
    pub fn get_port(&self) -> String {
      self.port.clone()
    }
  }

  // TODO: change to a struct with a builder pattern
  #[derive(Debug, Deserialize)]
  #[allow(unused)]
  struct ChainConfig {
    btc: bool,
    eth: bool,
    xmr: bool,
  }

  #[derive(Debug, Deserialize)]
  #[allow(unused)]
  struct HealthConfig {}

  impl HealthConfig {
    pub fn new() -> Self {
      Self {}
    }
  }

  #[derive(Debug, Deserialize)]
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

  #[derive(Debug, Deserialize)]
  #[allow(unused)]
  pub struct CoordinatorConfig {
    path: String,
    options: ConfigOption,
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
      let mode = ConfigOption::from_str(&run_mode).unwrap_or(ConfigOption::Development);

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
        ConfigOption::Development => {
          // Set development specific config
          println!("Development config loaded");
          Ok(config)
        }
        ConfigOption::Test => {
          // Set test specific config
          println!("Test config loaded");
          Ok(config)
        }
        ConfigOption::Production => {
          // Set production specific config
          println!("Production config loaded");
          Ok(config)
        }
      }
    }

    // get the config path
    pub fn get_path(&self) -> &str {
      &self.path
    }
    // get the config options
    pub fn get_options(&self) -> &ConfigOption {
      &self.options
    }
    // get the core config
    pub fn get_core(&self) -> &CoreConfig {
      &self.core
    }
    // get the health config
    pub fn get_health(&self) -> &HealthConfig {
      &self.health
    }
    // get the observer config
    pub fn get_observer(&self) -> &ObserverConfig {
      &self.observer
    }
  }

  struct CoordinatorLogger {
    
  }

  struct CoordinatorCore {

  }

  impl CoordinatorCore {
    pub fn new() -> Self {
      Self {}
    }
  }
