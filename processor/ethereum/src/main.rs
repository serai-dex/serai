#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc::wrap(std::alloc::System);

use core::time::Duration;
use std::sync::{Arc, OnceLock};

use alloy_core::primitives::U256;
use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{Provider as _, RootProvider};

use serai_primitives::validator_sets::Session;

use serai_db::{Get, DbTxn, create_db};

use ::primitives::EncodableG;
use ::key_gen::KeyGenParams as _;

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
  let (env, db) = bin::init().await;

  let provider = Arc::new(RootProvider::new(
    ClientBuilder::default().transport(SimpleRequest::new(bin::url(&env)).unwrap(), true),
  ));

  let chain_id = {
    let mut delay = Duration::from_secs(5);
    loop {
      match provider.get_chain_id().await {
        Ok(chain_id) => break U256::from(chain_id),
        Err(e) => {
          serai_env::error!("failed to fetch the chain ID on boot: {e:?}");
          tokio::time::sleep(delay).await;
          delay = (delay + Duration::from_secs(5)).min(Duration::from_mins(2));
        }
      }
    }
  };

  let router = Arc::new(OnceLock::new());
  let rpc = Rpc { db: db.clone(), provider: provider.clone(), router: router.clone() };
  if InitialSeraiKey::get(&db).is_some() {
    // Initialize the router now
    let mut delay = Duration::from_secs(5);
    loop {
      match rpc.initialize_router().await {
        Ok(()) => {
          assert!(router.get().is_some());
          break;
        }
        Err(e) => {
          serai_env::error!("failed find the router on boot: {e:?}");
          tokio::time::sleep(delay).await;
          delay = (delay + Duration::from_secs(5)).min(Duration::from_mins(2));
        }
      }
    }
  }

  let relayer_url = {
    let relayer_hostname =
      (**env.var("ETHEREUM_RELAYER_HOSTNAME").expect("ethereum relayer hostname wasn't specified"))
        .clone();
    let relayer_port =
      env.var("ETHEREUM_RELAYER_PORT").expect("ethereum relayer port wasn't specified");
    relayer_hostname + ":" + relayer_port
  };
  bin::main_loop::<SetInitialKey, _, KeyGenParams, _>(
    env,
    db.clone(),
    rpc,
    Scheduler::<bin::Db>::new(SmartContract { chain_id, router }),
    TransactionPublisher::new(db, provider, relayer_url),
  )
  .await;
}
