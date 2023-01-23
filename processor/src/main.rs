mod core;
mod signature;
use std::io;

use clap::{App, Arg};

use crate::core::ProcessorConfig;
use crate::core::CoreProcess;
use crate::signature::SignatureProcess;

#[tokio::main]
async fn main() {
  let args = App::new("Serai Processor")
    .version("0.1.0")
    .author("Serai Team")
    .about("Serai Processor")
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
        .short("d")
        .long("config_dir")
        .help(
          "The path that the coordinator can find relevant config files.
                   Default: ./config/",
        )
        .takes_value(true)
        .default_value("./config/"),
    )
    .arg(
      Arg::with_name("name")
        .short("n")
        .long("name")
        .help("This name is used as a unique prefix for kafka topics.")
        .takes_value(true)
        .default_value("base"),
    )
    .arg(
      Arg::with_name("chain")
        .short("c")
        .long("chain")
        .help("The chain to run the processor for.")
        .takes_value(true)
        .default_value("BTC"),
    )
    .get_matches();

  // Load Config / Chains
  let path_arg = args.value_of("config_dir").unwrap();

  // Load Coin argo
  let chain_arg = args.value_of("chain").unwrap();

  let config = ProcessorConfig::new(String::from(path_arg), String::from(chain_arg)).unwrap();

  // Load name arg
  let name_arg = args.value_of("name").unwrap().to_owned().to_lowercase();

  // Start Core Process
  let core_config = config.clone();
  let core_name_arg = name_arg.clone();
  tokio::spawn(async move {
    let core_process = CoreProcess::new(core_config.get_core(), core_config.get_coin());
    core_process.run(core_name_arg);
  });

  // Start Signature Process
  let sig_config = config.clone();
  tokio::spawn(async move {
    let signature_process =
      SignatureProcess::new(sig_config.get_coin(), sig_config.get_kafka(), name_arg);
    signature_process.run().await;
  });

  io::stdin().read_line(&mut String::new()).unwrap();
}
