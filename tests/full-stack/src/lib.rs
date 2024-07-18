use std::time::Duration;

use serai_client::Serai;

use dockertest::DockerOperations;

use serai_processor_tests::{RPC_USER, RPC_PASS};

#[cfg(test)]
mod tests;

#[allow(unused)]
#[derive(Clone, Debug)]
pub struct Handles {
  bitcoin: (String, u32),
  bitcoin_processor: String,
  monero: (String, u32),
  monero_processor: String,
  message_queue: String,
  serai: String,
}

impl Handles {
  pub async fn serai(&self, ops: &DockerOperations) -> Serai {
    let serai_rpc = ops.handle(&self.serai).host_port(9944).unwrap();
    let serai_rpc = format!("http://{}:{}", serai_rpc.0, serai_rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = Serai::new(serai_rpc.clone()).await else { continue };
      if client.latest_finalized_block_hash().await.is_err() {
        continue;
      }
      return client;
    }
    panic!("serai RPC server wasn't available after 60s");
  }

  pub async fn bitcoin(&self, ops: &DockerOperations) -> bitcoin_serai::rpc::Rpc {
    let rpc = ops.handle(&self.bitcoin.0).host_port(self.bitcoin.1).unwrap();
    let rpc = format!("http://{RPC_USER}:{RPC_PASS}@{}:{}", rpc.0, rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = bitcoin_serai::rpc::Rpc::new(rpc.clone()).await else { continue };
      return client;
    }
    panic!("bitcoin RPC server wasn't available after 60s");
  }

  pub async fn monero(
    &self,
    ops: &DockerOperations,
  ) -> monero_simple_request_rpc::SimpleRequestRpc {
    use monero_simple_request_rpc::SimpleRequestRpc;
    use monero_wallet::rpc::Rpc;

    let rpc = ops.handle(&self.monero.0).host_port(self.monero.1).unwrap();
    let rpc = format!("http://{RPC_USER}:{RPC_PASS}@{}:{}", rpc.0, rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = SimpleRequestRpc::new(rpc.clone()).await else { continue };
      if client.get_height().await.is_err() {
        continue;
      }
      return client;
    }
    panic!("monero RPC server wasn't available after 60s");
  }
}
