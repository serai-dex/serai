use core::future::Future;
use std::sync::Arc;

use alloy_rpc_types_eth::{BlockTransactionsKind, BlockNumberOrTag};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use serai_client::primitives::{NetworkId, Coin, Amount};

use scanner::ScannerFeed;

use crate::block::{Epoch, FullEpoch};

#[derive(Clone)]
pub(crate) struct Rpc {
  pub(crate) provider: Arc<RootProvider<SimpleRequest>>,
}

impl ScannerFeed for Rpc {
  const NETWORK: NetworkId = NetworkId::Ethereum;

  // We only need one confirmation as Ethereum properly finalizes
  const CONFIRMATIONS: u64 = 1;
  // The window length should be roughly an hour
  const WINDOW_LENGTH: u64 = 10;

  const TEN_MINUTES: u64 = 2;

  type Block = FullEpoch;

  type EphemeralError = String;

  fn latest_finalized_block_number(
    &self,
  ) -> impl Send + Future<Output = Result<u64, Self::EphemeralError>> {
    async move {
      let actual_number = self
        .provider
        .get_block(BlockNumberOrTag::Finalized.into(), BlockTransactionsKind::Hashes)
        .await
        .map_err(|e| format!("couldn't get the latest finalized block: {e:?}"))?
        .ok_or_else(|| "there was no finalized block".to_string())?
        .header
        .number;
      // Error if there hasn't been a full epoch yet
      if actual_number < 32 {
        Err("there has not been a completed epoch yet".to_string())?
      }
      // The divison by 32 returns the amount of completed epochs
      // Converting from amount of completed epochs to the latest completed epoch requires
      // subtracting 1
      let latest_full_epoch = (actual_number / 32) - 1;
      Ok(latest_full_epoch)
    }
  }

  fn time_of_block(
    &self,
    number: u64,
  ) -> impl Send + Future<Output = Result<u64, Self::EphemeralError>> {
    async move { todo!("TODO") }
  }

  fn unchecked_block_header_by_number(
    &self,
    number: u64,
  ) -> impl Send
       + Future<Output = Result<<Self::Block as primitives::Block>::Header, Self::EphemeralError>>
  {
    async move {
      let start = number * 32;
      let prior_end_hash = if start == 0 {
        [0; 32]
      } else {
        self
          .provider
          .get_block((start - 1).into(), BlockTransactionsKind::Hashes)
          .await
          .map_err(|e| format!("couldn't get block: {e:?}"))?
          .ok_or_else(|| {
            format!("ethereum node didn't have requested block: {number:?}. did we reorg?")
          })?
          .header
          .hash
          .into()
      };

      let end_header = self
        .provider
        .get_block((start + 31).into(), BlockTransactionsKind::Hashes)
        .await
        .map_err(|e| format!("couldn't get block: {e:?}"))?
        .ok_or_else(|| {
          format!("ethereum node didn't have requested block: {number:?}. did we reorg?")
        })?
        .header;

      let end_hash = end_header.hash.into();
      let time = end_header.timestamp;

      Ok(Epoch { prior_end_hash, start, end_hash, time })
    }
  }

  #[rustfmt::skip] // It wants to improperly format the `async move` to a single line
  fn unchecked_block_by_number(
    &self,
    number: u64,
  ) -> impl Send + Future<Output = Result<Self::Block, Self::EphemeralError>> {
    async move {
      todo!("TODO")
    }
  }

  fn dust(coin: Coin) -> Amount {
    assert_eq!(coin.network(), NetworkId::Ethereum);
    todo!("TODO")
  }

  fn cost_to_aggregate(
    &self,
    coin: Coin,
    _reference_block: &Self::Block,
  ) -> impl Send + Future<Output = Result<Amount, Self::EphemeralError>> {
    async move {
      assert_eq!(coin.network(), NetworkId::Ethereum);
      // TODO
      Ok(Amount(0))
    }
  }
}
