mod core;
mod kafka;
// Generates / secruely saves a coin specifik key pari on first launch or reloads
pub fn main(){
    println!("Starting processor");
    core::start_coin("btc");

    // Checks if coin keys exists, generates / sets env variables if not
    core::instantiate_keys();

    // Communicates public keys to partition
    kafka::start();
}
