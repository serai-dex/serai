use serai_db::{Db, DbTxn};

use primitives::{Id, ReceivedOutput, Block};

// TODO: Localize to ScanDb?
use crate::{db::ScannerDb, ScannerFeed, ContinuallyRan};

struct ScanForOutputsTask<D: Db, S: ScannerFeed> {
  db: D,
  feed: S,
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for ScanForOutputsTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    // Fetch the safe to scan block
    let latest_scannable = ScannerDb::<S>::latest_scannable_block(&self.db)
      .expect("ScanForOutputsTask run before writing the start block");
    // Fetch the next block to scan
    let next_to_scan = ScannerDb::<S>::next_to_scan_for_outputs_block(&self.db)
      .expect("ScanForOutputsTask run before writing the start block");

    for b in next_to_scan ..= latest_scannable {
      let block = match self.feed.block_by_number(b).await {
        Ok(block) => block,
        Err(e) => Err(format!("couldn't fetch block {b}: {e:?}"))?,
      };

      // Check the ID of this block is the expected ID
      {
        let expected =
          ScannerDb::<S>::block_id(&self.db, b).expect("scannable block didn't have its ID saved");
        if block.id() != expected {
          panic!(
            "finalized chain reorganized from {} to {} at {}",
            hex::encode(expected),
            hex::encode(block.id()),
            b
          );
        }
      }

      log::info!("scanning block: {} ({b})", hex::encode(block.id()));

      let mut keys =
        ScannerDb::<S>::keys(&self.db).expect("scanning for a blockchain without any keys set");
      // Remove all the retired keys
      while let Some(retire_at) = keys[0].retirement_block_number {
        if retire_at <= b {
          keys.remove(0);
        }
      }
      assert!(keys.len() <= 2);

      let mut outputs = vec![];
      // Scan for each key
      for key in keys {
        // If this key has yet to active, skip it
        if key.activation_block_number > b {
          continue;
        }

        for output in block.scan_for_outputs(key.key.0) {
          assert_eq!(output.key(), key.key.0);
          // TODO: Check for dust
          outputs.push(output);
        }
      }

      let mut txn = self.db.txn();
      // Save the outputs
      ScannerDb::<S>::set_outputs(&mut txn, b, outputs);
      // Update the next to scan block
      ScannerDb::<S>::set_next_to_scan_for_outputs_block(&mut txn, b + 1);
      txn.commit();
    }

    // Run dependents if we successfully scanned any blocks
    Ok(next_to_scan <= latest_scannable)
  }
}
