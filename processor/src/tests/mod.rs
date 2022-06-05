use std::sync::Arc;

use rand::rngs::OsRng;

use crate::{Coin, coins::monero::Monero, wallet::{WalletKeys, MemCoinDb, Wallet}};

#[tokio::test]
async fn test() {
  let monero = Monero::new("http://127.0.0.1:18081".to_string());
  println!("{}", monero.get_height().await.unwrap());
  let mut keys = frost::tests::key_gen::<_, <Monero as Coin>::Curve>(&mut OsRng);
  let mut wallet = Wallet::new(MemCoinDb::new(), monero);
  wallet.acknowledge_height(0, 0);
  wallet.add_keys(&WalletKeys::new(Arc::try_unwrap(keys.remove(&1).take().unwrap()).unwrap(), 0));
  dbg!(0);
}
