use std::env;
use message_box;
use group::ff::PrimeField;

// Accepts startup argument specifying which coin package to start
pub fn initialize_coin(coin: &str) {
  println!("Received Coin Request: {}", coin);

  match coin {
    "btc" => {}
    "eth" => {}
    "xmr" => {}
    _ => println!("coin unavailable {}", coin),
  }
}

// Generates Private / Public key pair
pub fn initialize_keys() {
  // Checks if coin keys are set
  let btc_priv_check = env::var("BTC_PRIV");
  if (btc_priv_check.is_err()) {
    // Generates new private / public key
    let (btc_private, btc_public) = message_box::key_gen();
    let mut btc_private_bytes = unsafe { btc_private.inner().to_repr() };
    // Sets private / public key to environment variables
    env::set_var("BTC_PRIV", hex::encode(btc_private_bytes.as_ref()));
    env::set_var("BTC_PUB", hex::encode(btc_public.to_bytes()));
  }

  let eth_priv_check = env::var("ETH_PRIV");
  if (eth_priv_check.is_err()) {
    // Generates new private / public key
    let (eth_private, eth_public) = message_box::key_gen();
    let mut eth_private_bytes = unsafe { eth_private.inner().to_repr() };
    // Sets private / public key to environment variables
    env::set_var("ETH_PRIV", hex::encode(eth_private_bytes.as_ref()));
    env::set_var("ETH_PUB", hex::encode(eth_public.to_bytes()));
  }

  let xmr_priv_check = env::var("XMR_PRIV");
  if (xmr_priv_check.is_err()) {
    // Generates new private / public key
    let (xmr_private, xmr_public) = message_box::key_gen();
    let mut xmr_private_bytes = unsafe { xmr_private.inner().to_repr() };
    // Sets private / public key to environment variables
    env::set_var("XMR_PRIV", hex::encode(xmr_private_bytes.as_ref()));
    env::set_var("XMR_PUB", hex::encode(xmr_public.to_bytes()));
  }
}
