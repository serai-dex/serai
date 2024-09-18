#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

use std::sync::Arc;

use alloy_core::primitives::U256;
use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{Provider, RootProvider};

use serai_env as env;

mod primitives;
pub(crate) use crate::primitives::*;

mod key_gen;
use crate::key_gen::KeyGenParams;
mod rpc;
use rpc::Rpc;
mod scheduler;
use scheduler::{SmartContract, Scheduler};
mod publisher;
use publisher::TransactionPublisher;

#[tokio::main]
async fn main() {
  let db = bin::init();
  let feed = {
    let provider = Arc::new(RootProvider::new(
      ClientBuilder::default().transport(SimpleRequest::new(bin::url()), true),
    ));
    Rpc { provider }
  };
  let chain_id = loop {
    match feed.provider.get_chain_id().await {
      Ok(chain_id) => break U256::try_from(chain_id).unwrap(),
      Err(e) => {
        log::error!("couldn't connect to the Ethereum node for the chain ID: {e:?}");
        tokio::time::sleep(core::time::Duration::from_secs(5)).await;
      }
    }
  };

  bin::main_loop::<_, KeyGenParams, _>(
    db,
    feed.clone(),
    Scheduler::new(SmartContract { chain_id }),
    TransactionPublisher::new({
      let relayer_hostname = env::var("ETHEREUM_RELAYER_HOSTNAME")
        .expect("ethereum relayer hostname wasn't specified")
        .to_string();
      let relayer_port =
        env::var("ETHEREUM_RELAYER_PORT").expect("ethereum relayer port wasn't specified");
      relayer_hostname + ":" + &relayer_port
    }),
  )
  .await;
}
