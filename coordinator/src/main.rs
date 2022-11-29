mod core;
mod health;
mod observer;
mod kafka_pubkey_producer;
mod kafka_message_producer;

use std::thread;
use std::io::Write;
use std::time::Duration;
use std::io;
use std::env;

use clap::{value_t, App, Arg};

use crate::core::CoordinatorConfig;
use crate::core::CoreProcess;

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

  // Initial Heartbeat to Processors
  //  * version check
  //  * binary checksum ??

  // Start Serai Observer
  observer::start();

  // Start Health Monitor

  // Start Network Broker

  // Hang on cli

  // Initialize Kafka
  kafka_pubkey_producer::start();

  // Runs a loop to check if all processor keys are found
  let mut all_keys_found = false;
  while !all_keys_found{
    let mut btc_key_found = false;
    let mut eth_key_found = false;
    let mut xmr_key_found = false;

    let btc_pub_check = env::var("BTC_PUB");
    if (!btc_pub_check.is_err()) {
      btc_key_found = true;
    }

    let eth_pub_check = env::var("ETH_PUB");
    if (!eth_pub_check.is_err()) {
      eth_key_found = true;
    }

    let xmr_pub_check = env::var("XMR_PUB");
    if (!xmr_pub_check.is_err()) {
      xmr_key_found = true;
    }

    if btc_key_found && eth_key_found && xmr_key_found {
      println!("All Processor Pubkeys Ready");
      all_keys_found = true;
    } else {
      thread::sleep(Duration::from_secs(1));
    }
  }

  // Start Public Observer
  observer::start_public_observer();

  // Start Encrypt Observer
  observer::start_encrypt_observer();

  // Send message from Coordinator to each Processor
  kafka_message_producer::send_message();

  io::stdin().read_line(&mut String::new()).unwrap();
}
