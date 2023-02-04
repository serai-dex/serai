use crate::{
  coin::{Coin, Monero},
  tests::{test_scan, test_signer, test_send},
};

sequential!();

async fn monero() -> Monero {
  let monero = Monero::new("http://127.0.0.1:18081".to_string()).await;
  while monero.get_latest_block_number().await.unwrap() < 150 {
    monero.mine_block().await;
  }
  monero
}

async_sequential! {
  async fn monero_scan() {
    test_scan(monero().await).await;
  }
}

async_sequential! {
  async fn monero_signer() {
    test_signer(monero().await).await;
  }
}

async_sequential! {
  async fn monero_send() {
    test_send(monero().await).await;
  }
}
