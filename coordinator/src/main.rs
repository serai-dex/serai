#![allow(unused_variables)]

use serai_db::{Db, MemDb};

use serai_client::Serai;

mod db;
pub use db::*;

mod transaction;
pub use transaction::Transaction as TributaryTransaction;

mod p2p;
pub use p2p::*;

mod substrate;

#[cfg(test)]
mod tests;

async fn run<D: Db, P: P2p>(db: D, p2p: P, serai: Serai) {
  let mut db = MainDb::new(db);

  let mut last_substrate_block = 0; // TODO: Load from DB

  loop {
    match substrate::handle_new_blocks(&mut db, &p2p, &serai, &mut last_substrate_block).await {
      Ok(()) => {}
      Err(e) => log::error!("couldn't communicate with serai node: {e}"),
    }

    // Handle all messages from tributaries

    // Handle all messages from processors
  }
}

#[tokio::main]
async fn main() {
  let db = MemDb::new(); // TODO
  let p2p = LocalP2p {}; // TODO
  let serai = || async {
    loop {
      let Ok(serai) = Serai::new("ws://127.0.0.1:9944").await else {
        log::error!("couldn't connect to the Serai node");
        continue
      };
      return serai;
    }
  };
  run(db, p2p, serai().await).await
}
