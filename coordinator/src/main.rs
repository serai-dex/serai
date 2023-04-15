#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]

use serai_db::Db;

use serai_client::Serai;

mod transaction;
mod substrate;

#[cfg(test)]
mod tests;

async fn run<D: Db>(db: D, serai: Serai) {
  let mut last_substrate_block = 0; // TODO: Load from DB

  loop {
    match substrate::handle_new_blocks(&serai, &mut last_substrate_block).await {
      Ok(()) => {}
      Err(e) => log::error!("couldn't communicate with serai node: {e}"),
    }

    // Handle all messages from tributaries

    // Handle all messages from processors
  }
}

#[tokio::main]
async fn main() {
  // Open the database
}
