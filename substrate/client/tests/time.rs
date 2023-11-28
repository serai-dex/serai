use std::time::{Duration, SystemTime};

use tokio::time::sleep;

use serai_client::Serai;

mod common;

serai_test!(
  time: (|serai: Serai| async move {
    let mut number = serai.latest_finalized_block().await.unwrap().number();
    let mut done = 0;
    while done < 3 {
      // Wait for the next block
      let block = serai.latest_finalized_block().await.unwrap();
      if block.number() == number {
        sleep(Duration::from_secs(1)).await;
        continue;
      }
      number = block.number();

      // Make sure the time we extract from the block is within 5 seconds of now
      let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
      assert!(now.saturating_sub(block.time().unwrap()) < 5);
      done += 1;
    }
  })
);
