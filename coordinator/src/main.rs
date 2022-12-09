mod core;
mod health;
mod signature;

use std::thread;
use std::io::Write;
use std::time::Duration;
use std::io;
use std::env;

use clap::{value_t, App, Arg};

use crate::core::CoordinatorConfig;
use crate::core::CoreProcess;
use crate::signature::SignatureProcess;

#[tokio::main]
async fn main() {
  let args = App::new("Serai Coordinator")
    .version("0.1.0")
    .author("Serai Team")
    .about("Serai Coordinator")
    .arg(
      Arg::with_name("mode")
        .short("m")
        .long("mode")
        .value_name("MODE")
        .help("Sets the mode to run in (Development, Test, Prodcution)")
        .takes_value(true)
        .default_value("Development"),
    )
    .arg(
      Arg::with_name("config_dir")
        .short("cd")
        .long("config_dir")
        .help(
          "The path that the coordinator can find relevant config files.
                     Default: ./config/",
        )
        .takes_value(true)
        .default_value("./config/"),
    )
    .arg(
      Arg::with_name("topic_id")
        .short("ti")
        .long("topic_id")
        .help("The id used as a unique prefix for kafka topics.")
        .takes_value(true)
        .default_value("default"),
    )
    .get_matches();

  // Load Config / Chains
  let path_arg = args.value_of("config_dir").unwrap();
  let config = CoordinatorConfig::new(String::from(path_arg)).unwrap();

  // Processes then use configs to create themselves

  // Start Core Process
  tokio::spawn(async move {
    let core_process = CoreProcess::new(config);
    core_process.run();
  });

  // Load kafka topic id
  let topic_id_arg = args.value_of("topic_id").unwrap();

  // Start Signature Process
  let sig_config = CoordinatorConfig::new(String::from(path_arg)).unwrap();
  tokio::spawn(async move {
    let signature_process = SignatureProcess::new(sig_config);
    signature_process.run();
  });

  // Initial Heartbeat to Processors
  //  * version check
  //  * binary checksum ??

  // Start Serai Observer

  // Start Health Monitor

  // Start Network Broker

  // Hang on cli
  io::stdin().read_line(&mut String::new()).unwrap();
}
