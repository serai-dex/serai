// Accepts startup argument specifying which coin package to start
pub fn start_coin(coin: &str) {
  println!("Received Coin Request: {}", coin);

  match coin {
    "btc" => {}
    "eth" => {}
    "xmr" => {}
    _ => println!("coin unavailable {}", coin),
  }
}
