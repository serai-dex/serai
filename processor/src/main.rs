mod core;
mod kafka_pubkey_producer;
mod kafka_encrypt_producer;
mod observer;
use std::io;

// Generates / secruely saves a coin specifik key pari on first launch or reloads
pub fn main(){
    println!("Starting processor");
    core::initialize_coin("btc");

    // Checks if coin keys exists, generates / sets env variables if not
    core::initialize_keys();

    // Starts Observer
    observer::start();

    // Communicates public keys to partition
    kafka_pubkey_producer::start();

    // Send Encrypted Message to Coordinator from each Processor
    kafka_encrypt_producer:: btc_send_message();
    kafka_encrypt_producer:: eth_send_message();
    kafka_encrypt_producer:: xmr_send_message();

    io::stdin().read_line(&mut String::new()).unwrap();
}
