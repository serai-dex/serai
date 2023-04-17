#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(clippy::diverging_sub_expression)]

use std::time::Duration;

use zeroize::Zeroizing;

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use serai_db::{Db, MemDb};
use serai_client::Serai;

use tokio::time::sleep;

mod db;
pub use db::*;

mod transaction;
pub use transaction::Transaction as TributaryTransaction;

mod p2p;
pub use p2p::*;

mod substrate;

#[cfg(test)]
mod tests;

async fn run<D: Db, P: P2p>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  serai: Serai,
) {
  let mut db = MainDb::new(db);

  let mut last_substrate_block = db.last_substrate_block();

  tokio::spawn(async move {
    loop {
      match substrate::handle_new_blocks(&mut db, &key, &p2p, &serai, &mut last_substrate_block)
        .await
      {
        Ok(()) => {}
        Err(e) => {
          log::error!("couldn't communicate with serai node: {e}");
          sleep(Duration::from_secs(5)).await;
        }
      }
    }
  });

  loop {
    // Handle all messages from tributaries

    // Handle all messages from processors

    todo!()
  }
}

#[tokio::main]
async fn main() {
  let db = MemDb::new(); // TODO
  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::ZERO); // TODO
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
  run(db, key, p2p, serai().await).await
}
