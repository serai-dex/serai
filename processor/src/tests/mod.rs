use std::{sync::{Arc, RwLock}, collections::HashMap};

use async_trait::async_trait;

use rand::rngs::OsRng;

use group::Group;

use crate::{
  NetworkError, Network,
  Coin, coins::monero::Monero,
  wallet::{WalletKeys, MemCoinDb, Wallet}
};

#[derive(Clone)]
struct LocalNetwork {
  i: u16,
  size: u16,
  round: usize,
  rounds: Arc<RwLock<Vec<HashMap<u16, Vec<u8>>>>>
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

    let res = self.rounds.try_read().unwrap()[self.round].clone();
    self.round += 1;
    Ok(res)
  }
}

#[tokio::test]
async fn test() {
  let monero = Monero::new("http://127.0.0.1:18081".to_string());
  // Mine a block so there's a confirmed height
  monero.mine_block(monero.address(dalek_ff_group::EdwardsPoint::generator())).await;
  let height = monero.get_height().await.unwrap();

  let mut networks = LocalNetwork::new(3);

  let mut keys = frost::tests::key_gen::<_, <Monero as Coin>::Curve>(&mut OsRng);
  let mut wallets = vec![];
  for i in 1 ..= 3 {
    let mut wallet = Wallet::new(MemCoinDb::new(), monero.clone());
    wallet.acknowledge_height(0, height);
    wallet.add_keys(
      &WalletKeys::new(Arc::try_unwrap(keys.remove(&i).take().unwrap()).unwrap(), 0)
    );
    wallets.push(wallet);
  }

  // Get the chain to a height where blocks have sufficient confirmations
  while (height + Monero::CONFIRMATIONS) > monero.get_height().await.unwrap() {
    monero.mine_block(monero.address(dalek_ff_group::EdwardsPoint::generator())).await;
  }

  for wallet in wallets.iter_mut() {
    // Poll to activate the keys
    wallet.poll().await.unwrap();
  }

  monero.test_send(wallets[0].address()).await;

  let mut futures = vec![];
  for (i, network) in networks.iter_mut().enumerate() {
    let wallet = &mut wallets[i];
    wallet.poll().await.unwrap();

    let height = monero.get_height().await.unwrap();
    wallet.acknowledge_height(1, height - 10);
    let signable = wallet.prepare_sends(
      1,
      vec![(wallet.address(), 10000000000)]
    ).await.unwrap().1.swap_remove(0);
    futures.push(monero.attempt_send(network, signable, &[1, 2, 3]));
  }
  println!(
    "{:?}",
    hex::encode(futures::future::join_all(futures).await.swap_remove(0).unwrap().0)
  );
}
