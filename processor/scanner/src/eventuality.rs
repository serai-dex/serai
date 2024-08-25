use serai_db::{Db, DbTxn};

use primitives::{OutputType, ReceivedOutput, Block};

// TODO: Localize to EventualityDb?
use crate::{lifetime::LifetimeStage, db::ScannerDb, ScannerFeed, ContinuallyRan};

/*
  Note: The following assumes there's some value, `CONFIRMATIONS`, and the finalized block we
  operate on is `CONFIRMATIONS` blocks deep. This is true for Proof-of-Work chains yet not the API
  actively used here.

  When we scan a block, we receive outputs. When this block is acknowledged, we accumulate those
  outputs into some scheduler, potentially causing certain transactions to begin their signing
  protocol.

  Despite only scanning blocks with `CONFIRMATIONS`, we cannot assume that these transactions (in
  their signed form) will only appear after `CONFIRMATIONS`. For `CONFIRMATIONS = 10`, the scanned
  block's number being `1`, the blockchain will have blocks with numbers `0 ..= 10`. While this
  implies the earliest the transaction will appear is when the block number is `11`, which is
  `1 + CONFIRMATIONS` (the number of the scanned block, plus the confirmations), this isn't
  guaranteed.

  A reorganization could occur which causes all unconfirmed blocks to be replaced, with the new
  blockchain having the signed transaction present immediately.

  This means that in order to detect Eventuality completions, we can only check block `b+1` once
  we've acknowledged block `b`, accumulated its outputs, triggered any transactions, and prepared
  for their Eventualities. This is important as both the completion of Eventualities, and the scan
  process, may cause a block to be considered notable (where notable blocks must be perfectly
  ordered).

  We do not want to fully serialize the scan flow solely because the Eventuality flow must be. If
  the time to scan, acknowledge, and intake a block ever exceeded the block time, we'd form a
  backlog.

  The solution is to form a window of blocks we can scan/acknowledge/intake, safely, such that we
  only form a backlog if the latency for a block exceeds the duration of the entire window (the
  amount of blocks in the window * the block time).

  By considering the block an Eventuality resolves not as the block it does, yet the block a window
  later, we enable the following flow:

  - The scanner scans within its window, submitting blocks for acknowledgement.
  - We have the blocks acknowledged (the consensus protocol handling this in parallel).
  - The scanner checks for Eventualities completed following acknowledged blocks.
  - If all Eventualities for a retiring multisig have been cleared, the notable block is one window
    later.
  - The start of the window shifts to the last block we've checked for Eventualities. This means
    the end of the window is the block we just set as notable, and yes, once that's scanned we can
    successfully publish a batch for it in a canonical fashion.

  This forms a backlog only if the latency of scanning, acknowledgement, and intake (including
  checking Eventualities) exceeds the window duration (the desired property).
*/
struct EventualityTask<D: Db, S: ScannerFeed> {
  db: D,
  feed: S,
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for EventualityTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    /*
      The set of Eventualities only increase when a block is acknowledged. Accordingly, we can only
      iterate up to (and including) the block currently pending acknowledgement. "including" is
      because even if block `b` causes new Eventualities, they'll only potentially resolve in block
      `b + 1`.

      We only know blocks will need acknowledgement *for sure* if they were scanned. The only other
      causes are key activation and retirement (both scheduled outside the scan window). This makes
      the exclusive upper bound the *next block to scan*.
    */
    let exclusive_upper_bound = {
      // Fetch the next to scan block
      let next_to_scan = ScannerDb::<S>::next_to_scan_for_outputs_block(&self.db)
        .expect("EventualityTask run before writing the start block");
      // If we haven't done any work, return
      if next_to_scan == 0 {
        return Ok(false);
      }
      next_to_scan
    };

    // Fetch the highest acknowledged block
    let highest_acknowledged = ScannerDb::<S>::highest_acknowledged_block(&self.db)
      .expect("EventualityTask run before writing the start block");

    // Fetch the next block to check
    let next_to_check = ScannerDb::<S>::next_to_check_for_eventualities_block(&self.db)
      .expect("EventualityTask run before writing the start block");

    // Check all blocks
    let mut iterated = false;
    for b in next_to_check .. exclusive_upper_bound {
      // If the prior block was notable *and* not acknowledged, break
      // This is so if it caused any Eventualities (which may resolve this block), we have them
      {
        // This `- 1` is safe as next to check is bound to be non-zero
        // This is possible since even if we receive coins in block 0, any transactions we'd make
        // would resolve in block 1 (the first block we'll check under this non-zero rule)
        let prior_block = b - 1;
        if ScannerDb::<S>::is_block_notable(&self.db, prior_block) &&
          (prior_block > highest_acknowledged)
        {
          break;
        }
      }

      iterated = true;

      // TODO: Add a helper to fetch an indexed block, de-duplicate with scan
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

      log::info!("checking eventuality completions in block: {} ({b})", hex::encode(block.id()));

      /*
        This is proper as the keys for the next to scan block (at most `WINDOW_LENGTH` ahead,
        which is `<= CONFIRMATIONS`) will be the keys to use here.

        If we had added a new key (which hasn't actually actived by the block we're currently
        working on), it won't have any Eventualities for at least `CONFIRMATIONS` blocks (so it'd
        have no impact here).

        As for retiring a key, that's done on this task's timeline. We ensure we don't bork the
        scanner by officially retiring the key `WINDOW_LENGTH` blocks in the future (ensuring the
        scanner never has a malleable view of the keys).
      */
      // TODO: Ensure the add key/remove key DB fns are called by the same task to prevent issues
      // there
      // TODO: On register eventuality, assert the above timeline assumptions
      let mut keys = ScannerDb::<S>::active_keys_as_of_next_to_scan_for_outputs_block(&self.db)
        .expect("scanning for a blockchain without any keys set");

      let mut txn = self.db.txn();

      // Fetch the External outputs we reported, and therefore should yield after handling this
      // block
      let mut outputs = ScannerDb::<S>::in_instructions(&txn, b)
        .expect("handling eventualities/outputs for block which didn't set its InInstructions")
        .into_iter()
        .map(|output| output.output)
        .collect::<Vec<_>>();

      for key in keys {
        let completed_eventualities = {
          let mut eventualities = ScannerDb::<S>::eventualities(&txn, key.key);
          let completed_eventualities = block.check_for_eventuality_resolutions(&mut eventualities);
          ScannerDb::<S>::set_eventualities(&mut txn, eventualities);
          completed_eventualities
        };

        // Fetch all non-External outputs
        let mut non_external_outputs = block.scan_for_outputs(key.key);
        non_external_outputs.retain(|output| output.kind() != OutputType::External);
        // Drop any outputs less than the dust limit
        non_external_outputs.retain(|output| {
          let balance = output.balance();
          balance.amount.0 >= self.feed.dust(balance.coin).0
        });

        /*
          Now that we have all non-External outputs, we filter them to be only the outputs which
          are from transactions which resolve our own Eventualities *if* the multisig is retiring.
          This implements step 6 of `spec/processor/Multisig Rotation.md`.

          We may receive a Change output. The only issue with accumulating this would be if it
          extends the multisig's lifetime (by increasing the amount of outputs yet to be
          forwarded). By checking it's one we made, either:
          1) It's a legitimate Change output to be forwarded
          2) It's a Change output created by a user burning coins (specifying the Change address),
             which can only be created while the multisig is actively handling `Burn`s (therefore
            ensuring this multisig cannot be kept alive ad-infinitum)

          The commentary on Change outputs also applies to Branch/Forwarded. They'll presumably get
          ignored if not usable however.
        */
        if key.stage == LifetimeStage::Finishing {
          non_external_outputs
            .retain(|output| completed_eventualities.contains_key(&output.transaction_id()));
        }

        // Now, we iterate over all Forwarded outputs and queue their InInstructions
        todo!("TODO");

        // Accumulate all of these outputs
        outputs.extend(non_external_outputs);
      }

      let outputs_to_return = ScannerDb::<S>::take_queued_returns(&mut txn, b);

      // Update the next to check block
      // TODO: Two-stage process
      ScannerDb::<S>::set_next_to_check_for_eventualities_block(&mut txn, next_to_check);
      txn.commit();
    }

    // Run dependents if we successfully checked any blocks
    Ok(iterated)
  }
}
