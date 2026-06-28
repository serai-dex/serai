use core::future::Future;

use monero_simple_request_rpc::{prelude::*, SimpleRequestTransport};

use serai_primitives::{network_id::ExternalNetworkId, coin::ExternalCoin, balance::Amount};

use scanner::ScannerFeed;
use signers::TransactionPublisher;

use crate::{
  transaction::Transaction,
  block::{BlockHeader, Block},
};

#[derive(Clone)]
pub(crate) struct Rpc {
  pub(crate) rpc: MoneroDaemon<SimpleRequestTransport>,
}

impl ScannerFeed for Rpc {
  const NETWORK: ExternalNetworkId = ExternalNetworkId::Monero;
  // Outputs aren't spendable until 10 blocks later due to the 10-block lock
  // Since we assumed scanned outputs are spendable, that sets a minimum confirmation depth of 10
  // A 10-block reorganization hasn't been observed in years and shouldn't occur
  const CONFIRMATIONS: u64 = 10;
  // The window length should be roughly an hour
  const WINDOW_LENGTH: u64 = 30;

  const TEN_MINUTES: u64 = 5;

  type Block = Block;

  type EphemeralError = InterfaceError;

  fn latest_finalized_block_number(
    &self,
  ) -> impl Send + Future<Output = Result<u64, Self::EphemeralError>> {
    async move {
      Ok(
        u64::try_from(self.rpc.latest_block_number().await?)
          .unwrap()
          .saturating_sub(Self::CONFIRMATIONS - 1),
      )
    }
  }

  fn time_of_block(
    &self,
    number: u64,
  ) -> impl Send + Future<Output = Result<u64, Self::EphemeralError>> {
    async move {
      // Constant from Monero
      const BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW: u64 = 60;

      // If Monero doesn't have enough blocks to build a window, it doesn't define a network time
      if (number + 1) < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW {
        return Ok(0);
      }

      // Fetch all the timestamps within the window
      let block_for_time_of = self.rpc.block_by_number(number.try_into().unwrap()).await?;
      let mut timestamps = vec![block_for_time_of.header.timestamp];
      let mut parent = block_for_time_of.header.previous;
      for _ in 1 .. BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW {
        let parent_block = self.rpc.block(parent).await?;
        timestamps.push(parent_block.header.timestamp);
        parent = parent_block.header.previous;
      }
      timestamps.sort_unstable();

      /*
        Because there are two timestamps equidistance from the ends, Monero's `epee` picks the
        in-between value, calculated by the following formula (from the "get_mid" function).

        `(a/2) + (b/2) + ((a - 2*(a/2)) + (b - 2*(b/2)))/2`

        This simplifies to `(a + b) / 2`. `(a/2) + (b/2)` ensures an overflow won't occur. Then,
        `((a - 2*(a/2)) + (b - 2*(b/2)))/2` is just a ridiculously complicated way to get the
        average last bit, flooring towards zero if only had its last bit set.
      */
      let n = timestamps.len() / 2;
      let a = timestamps[n - 1];
      let b = timestamps[n];
      let res = a.midpoint(b);

      // Monero does check that the new block's time is greater than the median, causing the median
      // to be monotonic
      Ok(res)
    }
  }

  fn unchecked_block_header_by_number(
    &self,
    number: u64,
  ) -> impl Send
       + Future<Output = Result<<Self::Block as primitives::Block>::Header, Self::EphemeralError>>
  {
    async move { Ok(BlockHeader(self.rpc.block_by_number(number.try_into().unwrap()).await?)) }
  }

  #[rustfmt::skip] // It wants to improperly format the `async move` to a single line
  fn unchecked_block_by_number(
    &self,
    number: u64,
  ) -> impl Send + Future<Output = Result<Self::Block, Self::EphemeralError>> {
    async move {
      Ok(Block(self.rpc.scannable_block_by_number(number.try_into().unwrap()).await?))
    }
  }

  fn dust(coin: ExternalCoin) -> Amount {
    assert_eq!(coin, ExternalCoin::Monero);

    // 0.01 XMR
    Amount(10_000_000_000)
  }

  fn cost_to_aggregate(
    &self,
    coin: ExternalCoin,
    _reference_block: &Self::Block,
  ) -> impl Send + Future<Output = Result<Amount, Self::EphemeralError>> {
    async move {
      assert_eq!(coin, ExternalCoin::Bitcoin);
      // TODO
      Ok(Amount(0))
    }
  }
}

impl TransactionPublisher<Transaction> for Rpc {
  type EphemeralError = PublishTransactionError;

  fn publish(
    &self,
    tx: Transaction,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>> {
    async move { self.rpc.publish_transaction(&tx.0).await }
  }
}

#[cfg(test)]
mod tests {
  use core::future::Future;
  use scanner::{ScannerFeed, tests};

  use monero_wallet::{address::Network, ViewPair};
  use monero_ed25519::{CompressedPoint, Scalar};
  use monero_simple_request_rpc::{SimpleRequestTransport, prelude::*};

  use zeroize::Zeroizing;

  static DAEMON_URL: &'static str = "http://serai:seraidex@127.0.0.1:18081";

  async fn add_block(rpc: &MoneroDaemon<SimpleRequestTransport>, block_count: usize) {
    rpc
      .generate_blocks(
        &ViewPair::new(CompressedPoint::G.decompress().unwrap(), Zeroizing::new(Scalar::ONE))
          .unwrap()
          .legacy_address(Network::Mainnet),
        block_count,
      )
      .await
      .unwrap();
  }

  async fn reset_chain(rpc: &MoneroDaemon<SimpleRequestTransport>) {
    let high_block_no = rpc.latest_block_number().await.unwrap();
    if high_block_no == 0 {
      return;
    }

    static DEFAULT_HIGH_RES_LIMIT: usize = 1000;

    let pop_n_blocks = format!(r#"{{"nblocks":{}}}"#, high_block_no);
    rpc.rpc_call("pop_blocks", Some(pop_n_blocks), DEFAULT_HIGH_RES_LIMIT).await.unwrap();
    rpc.json_rpc_call("flush_txpool", None, DEFAULT_HIGH_RES_LIMIT).await.unwrap();
  }

  #[derive(Clone)]
  struct DaemonHelper {
    pub(crate) rpc: MoneroDaemon<SimpleRequestTransport>,
  }

  impl tests::DaemonHelper for DaemonHelper {
    fn reset_chain(&self) -> impl Send + Future<Output = ()> {
      async move { reset_chain(&self.rpc).await }
    }

    fn add_block(&self) -> impl Send + Future<Output = ()> {
      async move { add_block(&self.rpc, 1).await }
    }

    /// We consider a Monero block "finalized" once it has 10 confirmations.
    fn setup_finalized_block(&self) -> impl Send + Future<Output = ()> {
      async move { add_block(&self.rpc, crate::Rpc::CONFIRMATIONS.try_into().unwrap()).await }
    }
  }

  #[tokio::test]
  async fn test_scanner() {
    // TODO: initialize a docker monerod instance for this test specifically

    let rpc = SimpleRequestTransport::new(DAEMON_URL.to_string()).await.unwrap();
    let feed = crate::Rpc { rpc: rpc.clone() };

    let daemon = DaemonHelper { rpc };

    tests::index_task_tests(feed.clone(), daemon).await;
  }
}
