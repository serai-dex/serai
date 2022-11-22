use std::sync::Arc;

use jsonrpsee::RpcModule;

use sp_blockchain::{Error as BlockchainError, HeaderBackend, HeaderMetadata};
use sc_transaction_pool_api::TransactionPool;
use sp_block_builder::BlockBuilder;
use sp_api::ProvideRuntimeApi;

use serai_runtime::{opaque::Block, opaque::BlockId, AccountId, Balance, Index};

pub struct KafkaDeps<C, P> {
  pub client: Arc<C>,
  pub pool: Arc<P>,
}

pub fn create_full<
  C: ProvideRuntimeApi<Block>
    + HeaderBackend<Block>
    + HeaderMetadata<Block, Error = BlockchainError>
    + 'static,
  P: TransactionPool + 'static,
>(
  deps: KafkaDeps<C, P>,
) -> KafkaModule<C,P>
where
  C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Index>
    + pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
    + BlockBuilder<Block>,
{
  use substrate_frame_rpc_system::{System, SystemApiServer};
  use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};

  let KafkaDeps { client, pool } = deps;
  let mut module = KafkaModule { deps: KafkaDeps { client: client, pool: pool } };
  return module;
}

pub struct KafkaModule<
  C: ProvideRuntimeApi<Block>
    + HeaderBackend<Block>
    + HeaderMetadata<Block, Error = BlockchainError>
    + 'static,
  P: TransactionPool + 'static,
> {
  pub deps: KafkaDeps<C, P>,
}

impl<
    C: ProvideRuntimeApi<Block>
      + HeaderBackend<Block>
      + HeaderMetadata<Block, Error = BlockchainError>
      + 'static,
    P: TransactionPool + 'static,
  > KafkaModule<C, P>
{
  /// Subscribes to substrate events and publishes block height
  /// changes to kafka.
  pub async fn run(&self) {
    // uses substrate client to subscribe to events
    // uses substrate client to subscribe to blocks
    let last = self.deps.client.info().finalized_hash;
    let api = self.deps.client.runtime_api();
    let session = api.current_session(&BlockId::Hash(last)).unwrap();
    let validators = api.validators(&BlockId::Hash(last)).unwrap();

    let mut finality_events = api.events().subscribe().await;

    while let Some(finality_events) = finality_events.next().await {
      for event in finality_events {
        match event {
          Ok(event) => {
            println!("Event: {:?}", event);
          }
          Err(e) => {
            println!("Error: {:?}", e);
          }
        }
      }
    }
  }
  // spawn a task that loops, awaiting for finality.next().await
}
