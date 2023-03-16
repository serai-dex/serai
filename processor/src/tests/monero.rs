use crate::{
  coin::{Coin, Monero},
  tests::test_send,
};

#[tokio::test]
async fn monero() {
  let monero = Monero::new("http://127.0.0.1:18081".to_string()).await;
  let fee = monero.get_fee().await;
  test_send(monero, fee).await;
}
