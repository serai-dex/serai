mod core;
mod kafka_pubkey;
mod observer;
// Generates / secruely saves a coin specifik key pari on first launch or reloads
pub fn main(){
    println!("Starting processor");
    core::initialize_coin("btc");

    // Checks if coin keys exists, generates / sets env variables if not
    core::initialize_keys();

    // Starts Observer
    observer::start();

    // Communicates public keys to partition
    kafka_pubkey::start();
}
