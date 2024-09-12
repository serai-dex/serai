#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

use monero_wallet::rpc::Rpc as MRpc;

mod primitives;
pub(crate) use crate::primitives::*;

/*
mod key_gen;
use crate::key_gen::KeyGenParams;
mod rpc;
use rpc::Rpc;
mod scheduler;
use scheduler::Scheduler;

#[tokio::main]
async fn main() {
  let db = bin::init();
  let feed = Rpc {
    db: db.clone(),
    rpc: loop {
      match MRpc::new(bin::url()).await {
        Ok(rpc) => break rpc,
        Err(e) => {
          log::error!("couldn't connect to the Monero node: {e:?}");
          tokio::time::sleep(core::time::Duration::from_secs(5)).await;
        }
      }
    },
  };

  bin::main_loop::<_, KeyGenParams, Scheduler<_>, Rpc<bin::Db>>(db, feed.clone(), feed).await;
}
*/

#[tokio::main]
async fn main() {}
