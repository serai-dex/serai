use monero_wallet::rpc::{RpcError, Rpc as RpcTrait};
use monero_simple_request_rpc::SimpleRequestRpc;

use serai_client::primitives::{NetworkId, Coin, Amount};

use scanner::ScannerFeed;
use signers::TransactionPublisher;

use crate::{
  transaction::Transaction,
  block::{BlockHeader, Block},
};

#[derive(Clone)]
pub(crate) struct Rpc {
  pub(crate) rpc: SimpleRequestRpc,
}

#[async_trait::async_trait]
impl ScannerFeed for Rpc {
  const NETWORK: NetworkId = NetworkId::Monero;
  // Outputs aren't spendable until 10 blocks later due to the 10-block lock
  // Since we assumed scanned outputs are spendable, that sets a minimum confirmation depth of 10
  // A 10-block reorganization hasn't been observed in years and shouldn't occur
  const CONFIRMATIONS: u64 = 10;
  // The window length should be roughly an hour
  const WINDOW_LENGTH: u64 = 30;

  const TEN_MINUTES: u64 = 5;

  type Block = Block;

  type EphemeralError = RpcError;

  async fn latest_finalized_block_number(&self) -> Result<u64, Self::EphemeralError> {
    Ok(self.rpc.get_height().await?.checked_sub(1).expect("connected to an invalid Monero RPC").try_into().unwrap())
  }

  async fn time_of_block(&self, number: u64) -> Result<u64, Self::EphemeralError> {
    todo!("TODO")
  }

  async fn unchecked_block_header_by_number(
    &self,
    number: u64,
  ) -> Result<<Self::Block as primitives::Block>::Header, Self::EphemeralError> {
    Ok(BlockHeader(
      self.rpc.get_block_by_number(number.try_into().unwrap()).await?
    ))
  }

  async fn unchecked_block_by_number(
    &self,
    number: u64,
  ) -> Result<Self::Block, Self::EphemeralError> {
    todo!("TODO")
  }

  fn dust(coin: Coin) -> Amount {
    assert_eq!(coin, Coin::Monero);

    todo!("TODO")
  }

  async fn cost_to_aggregate(
    &self,
    coin: Coin,
    _reference_block: &Self::Block,
  ) -> Result<Amount, Self::EphemeralError> {
    assert_eq!(coin, Coin::Bitcoin);
    // TODO
    Ok(Amount(0))
  }
}

#[async_trait::async_trait]
impl TransactionPublisher<Transaction> for Rpc {
  type EphemeralError = RpcError;

  async fn publish(&self, tx: Transaction) -> Result<(), Self::EphemeralError> {
    self.rpc.publish_transaction(&tx.0).await
  }
}
