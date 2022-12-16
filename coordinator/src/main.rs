mod core;
mod health;
mod signature;

use std::io;
use clap::{App, Arg};

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
        .value_name("mode")
        .help("Sets the mode to run in (Development, Test, Production)")
        .takes_value(true)
        .default_value("development"),
    )
    .arg(
      Arg::with_name("config_dir")
        .short("cd")
        .long("config_dir")
        .help(
          "The path that the coordinator can find relevant config files.
                     Default: ./config",
        )
        .takes_value(true)
        .default_value("./config"),
    )
    .arg(
      Arg::with_name("name")
        .short("id")
        .long("name")
        .help("This is the identity of the node running the coordinator and should match.")
        .takes_value(true)
        .default_value("BASE"),
    )
    .get_matches();

  // Load Config / Chains
  let path_arg = args.value_of("config_dir").unwrap();
  let config = CoordinatorConfig::new(String::from(path_arg)).unwrap();

  // Processes then use configs to create themselves

  // Start Core Process
  let core_config = config.clone();
  tokio::spawn(async move {
    let core_process = CoreProcess::new(core_config.get_core());
    core_process.run();
  });

  // Load identity arg
  let name_arg = args.value_of("name").unwrap().to_owned();

  // print identity arg
  println!("Coordinator Identity: {}", name_arg);

  // Start Signature Process
  let sig_config = config.clone();
  tokio::spawn(async move {
    let signature_process = SignatureProcess::new(sig_config.get_chain(), sig_config.get_kafka(), name_arg);
    signature_process.run().await;
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
