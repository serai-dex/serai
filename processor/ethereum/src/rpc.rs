use core::future::Future;
use std::{sync::Arc, collections::HashSet};

use alloy_core::primitives::B256;
use alloy_rpc_types_eth::{Header, BlockTransactionsKind, BlockNumberOrTag};
use alloy_transport::{RpcError, TransportErrorKind};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use serai_client::primitives::{NetworkId, Coin, Amount};

use tokio::task::JoinSet;

use serai_db::Db;

use scanner::ScannerFeed;

use ethereum_schnorr::PublicKey;
use ethereum_erc20::{TopLevelTransfer, Erc20};
#[rustfmt::skip]
use ethereum_router::{Coin as EthereumCoin, InInstruction as EthereumInInstruction, Executed, Router};

use crate::{
  TOKENS, ETHER_DUST, DAI_DUST, InitialSeraiKey,
  block::{Epoch, FullEpoch},
};

#[derive(Clone)]
pub(crate) struct Rpc<D: Db> {
  pub(crate) db: D,
  pub(crate) provider: Arc<RootProvider<SimpleRequest>>,
}

impl<D: Db> ScannerFeed for Rpc<D> {
  const NETWORK: NetworkId = NetworkId::Ethereum;

  // We only need one confirmation as Ethereum properly finalizes
  const CONFIRMATIONS: u64 = 1;
  // The window length should be roughly an hour
  const WINDOW_LENGTH: u64 = 10;

  const TEN_MINUTES: u64 = 2;

  type Block = FullEpoch;

  type EphemeralError = RpcError<TransportErrorKind>;

  fn latest_finalized_block_number(
    &self,
  ) -> impl Send + Future<Output = Result<u64, Self::EphemeralError>> {
    async move {
      let actual_number = self
        .provider
        .get_block(BlockNumberOrTag::Finalized.into(), BlockTransactionsKind::Hashes)
        .await?
        .ok_or_else(|| {
          TransportErrorKind::Custom("there was no finalized block".to_string().into())
        })?
        .header
        .number;
      // Error if there hasn't been a full epoch yet
      if actual_number < 32 {
        Err(TransportErrorKind::Custom(
          "there has not been a completed epoch yet".to_string().into(),
        ))?
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
    async move {
      let header = self
        .provider
        .get_block(BlockNumberOrTag::Number(number).into(), BlockTransactionsKind::Hashes)
        .await?
        .ok_or_else(|| {
          TransportErrorKind::Custom(
            "asked for time of a block our node doesn't have".to_string().into(),
          )
        })?
        .header;
      // This is monotonic ever since the merge
      // https://github.com/ethereum/consensus-specs/blob/4afe39822c9ad9747e0f5635cca117c18441ec1b
      //   /specs/bellatrix/beacon-chain.md?plain=1#L393-L394
      Ok(header.timestamp)
    }
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
          .await?
          .ok_or_else(|| {
            TransportErrorKind::Custom(
              format!("ethereum node didn't have requested block: {number:?}. was the node reset?")
                .into(),
            )
          })?
          .header
          .hash
          .into()
      };

      let end_header = self
        .provider
        .get_block((start + 31).into(), BlockTransactionsKind::Hashes)
        .await?
        .ok_or_else(|| {
          TransportErrorKind::Custom(
            format!("ethereum node didn't have requested block: {number:?}. was the node reset?")
              .into(),
          )
        })?
        .header;

      let end_hash = end_header.hash.into();

      Ok(Epoch { prior_end_hash, end_hash })
    }
  }

  fn unchecked_block_by_number(
    &self,
    number: u64,
  ) -> impl Send + Future<Output = Result<Self::Block, Self::EphemeralError>> {
    async move {
      let epoch = self.unchecked_block_header_by_number(number).await?;

      let Some(router) = Router::new(
        self.provider.clone(),
        &PublicKey::new(
          InitialSeraiKey::get(&self.db).expect("fetching a block yet never confirmed a key").0,
        )
        .expect("initial key used by Serai wasn't representable on Ethereum"),
      )
      .await?
      else {
        Err(TransportErrorKind::Custom("router wasn't deployed on-chain yet".to_string().into()))?
      };

      async fn sync_block(
        provider: Arc<RootProvider<SimpleRequest>>,
        router: Router,
        block: Header,
      ) -> Result<(Vec<EthereumInInstruction>, Vec<Executed>), RpcError<TransportErrorKind>> {
        let mut instructions = router.in_instructions(block.number, &HashSet::from(TOKENS)).await?;

        for token in TOKENS {
          for TopLevelTransfer { id, from, amount, data } in Erc20::new(provider.clone(), token)
            .top_level_transfers(block.number, router.address())
            .await?
          {
            instructions.push(EthereumInInstruction {
              id,
              from,
              coin: EthereumCoin::Erc20(token),
              amount,
              data,
            });
          }
        }

        let executed = router.executed(block.number).await?;

        Ok((instructions, executed))
      }

      // We use JoinSet here to minimize the latency of the variety of requests we make. For each
      // JoinError that may occur, we unwrap it as no underlying tasks should panic
      let mut join_set = JoinSet::new();
      let mut to_check = epoch.end_hash;
      // TODO: This makes 32 sequential requests. We should run them in parallel using block
      // nunbers
      while to_check != epoch.prior_end_hash {
        let to_check_block = self
          .provider
          .get_block(B256::from(to_check).into(), BlockTransactionsKind::Hashes)
          .await?
          .ok_or_else(|| {
            TransportErrorKind::Custom(
              format!(
                "ethereum node didn't have requested block: {}. was the node reset?",
                hex::encode(to_check)
              )
              .into(),
            )
          })?
          .header;

        // Update the next block to check
        to_check = *to_check_block.parent_hash;

        // Spawn a task to sync this block
        join_set.spawn(sync_block(self.provider.clone(), router.clone(), to_check_block));
      }

      let mut instructions = vec![];
      let mut executed = vec![];
      while let Some(instructions_and_executed) = join_set.join_next().await {
        let (mut these_instructions, mut these_executed) = instructions_and_executed.unwrap()?;
        instructions.append(&mut these_instructions);
        executed.append(&mut these_executed);
      }

      Ok(FullEpoch { epoch, instructions, executed })
    }
  }

  fn dust(coin: Coin) -> Amount {
    assert_eq!(coin.network(), NetworkId::Ethereum);
    match coin {
      Coin::Ether => ETHER_DUST,
      Coin::Dai => DAI_DUST,
      _ => unreachable!(),
    }
  }

  fn cost_to_aggregate(
    &self,
    coin: Coin,
    _reference_block: &Self::Block,
  ) -> impl Send + Future<Output = Result<Amount, Self::EphemeralError>> {
    async move {
      assert_eq!(coin.network(), NetworkId::Ethereum);
      // There is no cost to aggregate as we receive to an account
      Ok(Amount(0))
    }
  }
}
