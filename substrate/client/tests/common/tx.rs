use core::time::Duration;

use tokio::time::sleep;

use serai_client::Serai;

#[allow(dead_code)]
pub async fn publish_tx(serai: &Serai, tx: &[u8]) -> [u8; 32] {
  let mut latest =
    serai.block(serai.latest_block_hash().await.unwrap()).await.unwrap().unwrap().number();

  serai.publish(tx).await.unwrap();

  // Get the block it was included in
  // TODO: Add an RPC method for this/check the guarantee on the subscription
  let mut ticks = 0;
  loop {
    latest += 1;

    let block = {
      let mut block;
      while {
        block = serai.block_by_number(latest).await.unwrap();
        block.is_none()
      } {
        sleep(Duration::from_secs(1)).await;
        ticks += 1;

        if ticks > 60 {
          panic!("60 seconds without inclusion in a finalized block");
        }
      }
      block.unwrap()
    };

    for transaction in block.transactions() {
      if transaction.0 == tx {
        return block.hash();
      }
    }
  }
}
