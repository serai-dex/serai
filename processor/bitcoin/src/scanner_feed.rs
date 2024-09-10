use bitcoin_serai::rpc::{RpcError, Rpc as BRpc};

use serai_client::primitives::{NetworkId, Coin, Amount};

use scanner::ScannerFeed;

use crate::block::{BlockHeader, Block};

#[derive(Clone)]
pub(crate) struct Rpc(BRpc);

#[async_trait::async_trait]
impl ScannerFeed for Rpc {
  const NETWORK: NetworkId = NetworkId::Bitcoin;
  const CONFIRMATIONS: u64 = 6;
  const WINDOW_LENGTH: u64 = 6;

  const TEN_MINUTES: u64 = 1;

  type Block = Block;

  type EphemeralError = RpcError;

  async fn latest_finalized_block_number(&self) -> Result<u64, Self::EphemeralError> {
    u64::try_from(self.0.get_latest_block_number().await?)
      .unwrap()
      .checked_sub(Self::CONFIRMATIONS)
      .ok_or(RpcError::ConnectionError)
  }

  async fn unchecked_block_header_by_number(
    &self,
    number: u64,
  ) -> Result<<Self::Block as primitives::Block>::Header, Self::EphemeralError> {
    Ok(BlockHeader(
      self.0.get_block(&self.0.get_block_hash(number.try_into().unwrap()).await?).await?.header,
    ))
  }

  async fn unchecked_block_by_number(
    &self,
    number: u64,
  ) -> Result<Self::Block, Self::EphemeralError> {
    Ok(Block(self.0.get_block(&self.0.get_block_hash(number.try_into().unwrap()).await?).await?))
  }

  fn dust(coin: Coin) -> Amount {
    assert_eq!(coin, Coin::Bitcoin);
    // 10,000 satoshis, or $5 if 1 BTC = 50,000 USD
    Amount(10_000)
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
