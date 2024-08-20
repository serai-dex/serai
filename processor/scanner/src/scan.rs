use serai_db::{Db, DbTxn};

use primitives::{Id, Block};

// TODO: Localize to ScanDb?
use crate::{db::ScannerDb, ScannerFeed};

struct ScanForOutputsTask<D: Db, S: ScannerFeed> {
  db: D,
  feed: S,
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for ScanForOutputsTask<D, S> {
  async fn run_instance(&mut self) -> Result<(), String> {
    // Fetch the safe to scan block
    let latest_scannable = ScannerDb::<S>::latest_scannable_block(&self.db).expect("ScanForOutputsTask run before writing the start block");
    // Fetch the next block to scan
    let next_to_scan = ScannerDb::<S>::next_to_scan_for_outputs_block(&self.db).expect("ScanForOutputsTask run before writing the start block");

    for b in next_to_scan ..= latest_scannable {
      let block = match self.feed.block_by_number(b).await {
        Ok(block) => block,
        Err(e) => Err(format!("couldn't fetch block {b}: {e:?}"))?,
      };

      // Check the ID of this block is the expected ID
      {
        let expected = ScannerDb::<S>::block_id(b).expect("scannable block didn't have its ID saved");
        if block.id() != expected {
          panic!("finalized chain reorganized from {} to {} at {}", hex::encode(expected), hex::encode(block.id()), b);
        }
      }

      log::info!("scanning block: {} ({b})", hex::encode(block.id()));

      let keys = ScannerDb::<S>::keys(&self.db).expect("scanning for a blockchain without any keys set");
      // Remove all the retired keys
      while let Some(retire_at) = keys[0].retirement_block_number {
        if retire_at <= b {
          keys.remove(0);
        }
      }
      assert!(keys.len() <= 2);

      // Scan for each key
      for key in keys {
        // If this key has yet to active, skip it
        if key.activation_block_number > b {
          continue;
        }

        let mut outputs = vec![];
        for output in network.scan_for_outputs(&block, key).awaits {
          assert_eq!(output.key(), key);
          // TODO: Check for dust
          outputs.push(output);
        }
      }

      let mut txn = self.db.txn();
      // Update the latest scanned block
      ScannerDb::<S>::set_next_to_scan_for_outputs_block(&mut txn, b + 1);
      // TODO: If this had outputs, yield them and mark this block notable
      /*
        A block is notable if it's an activation, had outputs, or a retirement block.
      */
      txn.commit();
    }

    Ok(())
  }
}
