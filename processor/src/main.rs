mod core;
mod signature;
use std::io;
use std::env;
use std::time::Duration;
use std::thread;
use std::io::Write;

use clap::{value_t, App, Arg};

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
      Arg::with_name("identity")
        .short("id")
        .long("identity")
        .help("This identity is used as a unique prefix for kafka topics.")
        .takes_value(true)
        .default_value("default"),
    )
    .get_matches();

  // Load Config / Chains
  let path_arg = args.value_of("config_dir").unwrap();
  let config = ProcessorConfig::new(String::from(path_arg)).unwrap();

  // Start Core Process
  tokio::spawn(async move {
    let core_process = CoreProcess::new(config);
    core_process.run();
  });

  // Load kafka topic id
  let topic_id_arg = args.value_of("topic_identity").unwrap();

  // Start Signature Process
  let sig_config = ProcessorConfig::new(String::from(path_arg)).unwrap();
  tokio::spawn(async move {
    let signature_process = SignatureProcess::new(sig_config);
    signature_process.run();
  });

  io::stdin().read_line(&mut String::new()).unwrap();
}
