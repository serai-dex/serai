use crate::{
  coin::Monero,
  tests::{test_scan, test_send},
};

sequential!();

async fn monero() -> Monero {
  Monero::new("http://127.0.0.1:18081".to_string()).await
}

async_sequential! {
  async fn monero_send() {
    test_send(monero().await).await;
  }
}

async_sequential! {
  async fn monero_scan() {
    test_scan(monero().await).await;
  }
}
