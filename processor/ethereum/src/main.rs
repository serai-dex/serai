#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

use core::time::Duration;
use std::sync::Arc;

use alloy_core::primitives::U256;
use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{Provider, RootProvider};

use serai_client::validator_sets::primitives::Session;

use serai_env as env;
use serai_db::{Get, DbTxn, create_db};

use ::primitives::EncodableG;
use ::key_gen::KeyGenParams as KeyGenParamsTrait;

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

create_db! {
  EthereumProcessor {
    // The initial key for Serai on Ethereum
    InitialSeraiKey: () -> EncodableG<k256::ProjectivePoint>,
  }
}

struct SetInitialKey;
impl bin::Hooks for SetInitialKey {
  fn on_message(txn: &mut impl DbTxn, msg: &messages::CoordinatorMessage) {
    if let messages::CoordinatorMessage::Substrate(
      messages::substrate::CoordinatorMessage::SetKeys { session, key_pair, .. },
    ) = msg
    {
      assert_eq!(*session, Session(0));
      let key = KeyGenParams::decode_key(key_pair.1.as_ref())
        .expect("invalid Ethereum key confirmed on Substrate");
      InitialSeraiKey::set(txn, &EncodableG(key));
    }
  }
}

#[tokio::main]
async fn main() {
  let db = bin::init();

  let provider = Arc::new(RootProvider::new(
    ClientBuilder::default().transport(SimpleRequest::new(bin::url()), true),
  ));

  let chain_id = {
    let mut delay = Duration::from_secs(5);
    loop {
      match provider.get_chain_id().await {
        Ok(chain_id) => break chain_id,
        Err(e) => {
          log::error!("failed to fetch the chain ID on boot: {e:?}");
          tokio::time::sleep(delay).await;
          delay = (delay + Duration::from_secs(5)).max(Duration::from_secs(120));
        }
      }
    }
  };

  bin::main_loop::<SetInitialKey, _, KeyGenParams, _>(
    db.clone(),
    Rpc { db: db.clone(), provider: provider.clone() },
    Scheduler::<bin::Db>::new(SmartContract {
      chain_id: U256::from_le_slice(&chain_id.to_le_bytes()),
    }),
    TransactionPublisher::new(db, provider, {
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
