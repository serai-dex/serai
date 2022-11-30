mod core;
mod kafka_pubkey_producer;
mod kafka_message_producer;
mod observer;
use std::io;
use std::env;
use std::time::Duration;
use std::thread;

// Generates / secruely saves a coin specifik key pari on first launch or reloads
pub fn main() {
  println!("Starting processor");
  core::initialize_coin("btc");

  // Checks if coin keys exists, generates / sets env variables if not
  core::initialize_keys();

  // Starts Observer
  observer::start();

  // Communicates public keys to partition
  kafka_pubkey_producer::start();

  // Runs a loop to check if Coordinator pubkey is found
  let mut coord_key_found = false;
  while !coord_key_found {
    let coord_pub_check = env::var("COORD_PUB");
    if (!coord_pub_check.is_err()) {
      println!("Coord Pubkey Ready");
      coord_key_found = true;
    } else {
      thread::sleep(Duration::from_secs(1));
    }
  }

  // Start public Observer
  observer::start_public_observer();

  // Start Encrypt Observer
  observer::start_encrypt_observer();

  // // Send Encrypted Message to Coordinator from each Processor
  kafka_message_producer::send_messages();

  io::stdin().read_line(&mut String::new()).unwrap();
}
