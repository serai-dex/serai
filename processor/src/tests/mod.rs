use std::{
  sync::{Arc, RwLock},
  collections::HashMap,
};

use async_trait::async_trait;

use rand_core::OsRng;

use crate::{
  NetworkError, Network,
  coin::{Coin, Monero},
  wallet::{WalletKeys, MemCoinDb, Wallet},
};

#[derive(Clone)]
struct LocalNetwork {
  i: u16,
  size: u16,
  round: usize,
  rounds: Arc<RwLock<Vec<HashMap<u16, Vec<u8>>>>>,
}

impl LocalNetwork {
  fn new(size: u16) -> Vec<LocalNetwork> {
    let rounds = Arc::new(RwLock::new(vec![]));
    let mut res = vec![];
    for i in 1 ..= size {
      res.push(LocalNetwork { i, size, round: 0, rounds: rounds.clone() });
    }
    res
  }
}

#[async_trait]
impl Network for LocalNetwork {
  async fn round(&mut self, data: Vec<u8>) -> Result<HashMap<u16, Vec<u8>>, NetworkError> {
    {
      let mut rounds = self.rounds.write().unwrap();
      if rounds.len() == self.round {
        rounds.push(HashMap::new());
      }
      rounds[self.round].insert(self.i, data);
    }

    while {
      let read = self.rounds.try_read().unwrap();
      read[self.round].len() != usize::from(self.size)
    } {
      tokio::task::yield_now().await;
    }

    let mut res = self.rounds.try_read().unwrap()[self.round].clone();
    res.remove(&self.i);
    self.round += 1;
    Ok(res)
  }
}

async fn test_send<C: Coin + Clone>(coin: C, fee: C::Fee) {
  // Mine blocks so there's a confirmed block
  coin.mine_block().await;
  let latest = coin.get_latest_block_number().await.unwrap();

  let mut keys = frost::tests::key_gen::<_, C::Curve>(&mut OsRng);
  let threshold = keys[&1].params().t();
  let mut networks = LocalNetwork::new(threshold);

  let mut wallets = vec![];
  for i in 1 ..= threshold {
    let mut wallet = Wallet::new(MemCoinDb::new(), coin.clone());
    wallet.acknowledge_block(0, latest);
    wallet.add_keys(&WalletKeys::new(keys.remove(&i).unwrap(), 0));
    wallets.push(wallet);
  }

  // Get the chain to a length where blocks have sufficient confirmations
  while (latest + (C::CONFIRMATIONS - 1)) > coin.get_latest_block_number().await.unwrap() {
    coin.mine_block().await;
  }

  for wallet in wallets.iter_mut() {
    // Poll to activate the keys
    wallet.poll().await.unwrap();
  }

  coin.test_send(wallets[0].address()).await;

  let mut futures = vec![];
  for (network, wallet) in networks.iter_mut().zip(wallets.iter_mut()) {
    wallet.poll().await.unwrap();

    let latest = coin.get_latest_block_number().await.unwrap();
    wallet.acknowledge_block(1, latest - (C::CONFIRMATIONS - 1));
    let signable = wallet
      .prepare_sends(1, vec![(wallet.address(), 10000000000)], fee)
      .await
      .unwrap()
      .1
      .swap_remove(0);
    futures.push(wallet.attempt_send(network, signable));
  }

  println!("{:?}", hex::encode(futures::future::join_all(futures).await.swap_remove(0).unwrap().0));
}

#[tokio::test]
async fn monero() {
  let monero = Monero::new("http://127.0.0.1:18081".to_string()).await;
  let fee = monero.get_fee().await;
  test_send(monero, fee).await;
}
