mod core;
mod health;
mod signature;
mod observer;

#[path = "test/kafka_test.rs"]
mod kafka_test;

#[path = "test/message_box_test.rs"]
mod message_box_test;

use std::io;
use clap::{App, Arg};

use crate::core::CoordinatorConfig;
use crate::core::CoreProcess;
use crate::signature::SignatureProcess;
use log::{error, info};
mod network;
use crate::network::NetworkProcess;

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
        .short("d")
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
        .short("n")
        .long("name")
        .help("This is the name of the node running the coordinator and should match.")
        .takes_value(true)
        .default_value("base"),
    )
    .get_matches();

  // Load Config / Chains
  let path_arg = args.value_of("config_dir").unwrap();
  let config = CoordinatorConfig::new(String::from(path_arg)).unwrap();

  // Load identity arg
  let name_arg = args.value_of("name").unwrap().to_owned().to_lowercase();

  // print identity arg
  info!("Coordinator Identity: {}", name_arg);

  // Processes then use configs to create themselves

  // Start Core Process
  let core_config = config.clone();
  let core_kafka_config = config.clone().get_kafka();
  let core_name_arg = name_arg.to_string().to_owned();

  tokio::spawn(async move {
    let core_process = CoreProcess::new(core_config.get_core(), core_config.get_chain(), core_kafka_config.clone());
    core_process.run(core_name_arg).await;
  }).await.unwrap();

  // Start Signature Process
  let sig_config = config.clone();
  let sig_kafka_config = config.clone().get_kafka();
  let sig_name_arg = name_arg.to_string().to_owned();
  tokio::spawn(async move {
    let signature_process =
      SignatureProcess::new(sig_config.get_chain(), sig_kafka_config.clone(), sig_name_arg);
    signature_process.run().await;
  });
  

  // Initial Heartbeat to Processors
  //  * version check
  //  * binary checksum ??
  let observer_config = config.clone().get_observer();
  let observer_kafka_config = config.clone().get_kafka();
  let observer_name_arg = name_arg.to_string().to_owned();
  // Start Serai Observer
  tokio::spawn(async move {
    let observer_process = observer::ObserverProcess::new(observer_config, observer_kafka_config.clone(), observer_name_arg);
    observer_process.run().await.unwrap();
  });

  // Start Health Monitor

  // Start Network Broker

  // Start Network Process
  let network_config = config.clone();
  let network_name_arg = name_arg.to_string().to_owned();

  let network_process = NetworkProcess::new(network_name_arg.to_string(), network_config.get_network().signers);
  network_process.run(network_config.get_chain(), network_config.get_kafka()).await;
}
