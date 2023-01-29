use lazy_static::lazy_static;

use crate::{
  coin::{Coin, Monero},
  tests::{test_scan, test_send},
};

sequential!();

async fn monero() -> Monero {
  Monero::new("http://127.0.0.1:18081".to_string()).await
}

async_sequential! {
  async fn monero_send() {
    let monero = monero().await;
    let fee = monero.get_fee().await;
    test_send(monero, fee).await;
  }
}

async_sequential! {
  async fn monero_scan() {
    test_scan(monero().await).await;
  }
}
