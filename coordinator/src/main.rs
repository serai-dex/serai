#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(clippy::diverging_sub_expression)]

use std::{time::Duration, collections::HashMap};

use zeroize::Zeroizing;

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use serai_db::{Db, MemDb};
use serai_client::Serai;

use tokio::time::sleep;

mod tributary;

mod p2p;
pub use p2p::*;

pub mod processor;
use processor::Processor;

mod substrate;

#[cfg(test)]
pub mod tests;

async fn run<D: Db, Pro: Processor, P: P2p>(
  raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  mut processor: Pro,
  serai: Serai,
) {
  let mut substrate_db = substrate::SubstrateDb::new(raw_db.clone());
  let mut last_substrate_block = substrate_db.last_block();
  let mut last_tributary_block = HashMap::<[u8; 32], _>::new();

  {
    let key = key.clone();
    let mut processor = processor.clone();
    tokio::spawn(async move {
      loop {
        match substrate::handle_new_blocks(
          &mut substrate_db,
          &key,
          &p2p,
          &mut processor,
          &serai,
          &mut last_substrate_block,
        )
        .await
        {
          Ok(()) => sleep(Duration::from_secs(3)).await,
          Err(e) => {
            log::error!("couldn't communicate with serai node: {e}");
            sleep(Duration::from_secs(5)).await;
          }
        }
      }
    });
  }

  {
    let mut tributary_db = tributary::TributaryDb::new(raw_db);
    tokio::spawn(async move {
      loop {
        for (_, last_block) in last_tributary_block.iter_mut() {
          tributary::scanner::handle_new_blocks::<_, _, P>(
            &mut tributary_db,
            &key,
            &mut processor,
            todo!(),
            todo!(),
            last_block,
          )
          .await;
        }
        sleep(Duration::from_secs(3)).await;
      }
    });
  }

  loop {
    // Handle all messages from processors
    todo!()
  }
}

#[tokio::main]
async fn main() {
  let db = MemDb::new(); // TODO

  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::ZERO); // TODO
  let p2p = LocalP2p::new(1).swap_remove(0); // TODO

  let processor = processor::MemProcessor::new(); // TODO

  let serai = || async {
    loop {
      let Ok(serai) = Serai::new("ws://127.0.0.1:9944").await else {
        log::error!("couldn't connect to the Serai node");
        sleep(Duration::from_secs(5)).await;
        continue
      };
      return serai;
    }
  };
  run(db, key, p2p, processor, serai().await).await
}
