use crate::{Coin, coins::monero::Monero};

#[tokio::test]
async fn test() {
  println!("{}", Monero::new("http://127.0.0.1:18081".to_string()).get_height().await.unwrap());
}
