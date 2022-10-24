mod core;
mod health;
mod observer;

use std::thread;
use std::io::Write;
use std::time::Duration;

use clap::{value_t, App, Arg};

use crate::core::CoordinatorConfig;

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
            Arg::with_name("config")
                .short("c")
                .long("config")
                .help(
                    "The path that the coordinator can find relevant config files.
                     Default: ./config/")
                .takes_value(true)
                .default_value("./config/"),
        )
        .get_matches();

    // Load Config / Chains
    let path_arg = args.value_of("config").unwrap();
    let result = CoordinatorConfig::new(String::from(path_arg));
    let config = match result {
        Ok(config) => config,
        Err(err) => {
            println!("Error loading config: {}", err);
            return;
        }
    };

    // Setup Logger

    // Initial Heartbeat to Processors
    //  * version check
    //  * binary checksum ??

    // Start Serai Observer

    // Start Health Monitor

    // Start Network Broker

    // Start Persistence

    // Hang on cli

}