use std::collections::HashMap;

use scale::Decode;
use serai_db::{Get, DbTxn, Db};

use serai_primitives::MAX_DATA_LEN;
use serai_in_instructions_primitives::{
  Shorthand, RefundableInInstruction, InInstruction, InInstructionWithBalance,
};

use primitives::{task::ContinuallyRan, OutputType, ReceivedOutput, Block};

use crate::{
  lifetime::LifetimeStage,
  db::{
    OutputWithInInstruction, Returnable, SenderScanData, ScannerGlobalDb, ScanToReportDb,
    ScanToEventualityDb,
  },
  BlockExt, ScannerFeed, AddressFor, OutputFor, Return, sort_outputs,
  eventuality::latest_scannable_block,
};

mod db;
use db::ScanDb;

pub(crate) fn next_to_scan_for_outputs_block<S: ScannerFeed>(getter: &impl Get) -> Option<u64> {
  ScanDb::<S>::next_to_scan_for_outputs_block(getter)
}

pub(crate) fn queue_output_until_block<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  queue_for_block: u64,
  output: &OutputWithInInstruction<S>,
) {
  // This isn't a perfect assertion as by the time this txn commits, we may have already started
  // scanning this block. That doesn't change it should never trip as we queue outside the window
  // we'll scan
  assert!(
    queue_for_block >=
      next_to_scan_for_outputs_block::<S>(txn)
        .expect("queueing an output despite no next-to-scan-for-outputs block"),
    "queueing an output for a block already scanned"
  );
  ScanDb::<S>::queue_output_until_block(txn, queue_for_block, output)
}

// Construct an InInstruction from an external output.
//
// Also returns the address to return the coins to upon error.
fn in_instruction_from_output<S: ScannerFeed>(
  output: &OutputFor<S>,
) -> (Option<AddressFor<S>>, Option<InInstruction>) {
  assert_eq!(output.kind(), OutputType::External);

  let presumed_origin = output.presumed_origin();

  let mut data = output.data();
  let max_data_len = usize::try_from(MAX_DATA_LEN).unwrap();
  if data.len() > max_data_len {
    log::info!(
      "data in output {} exceeded MAX_DATA_LEN ({MAX_DATA_LEN}): {}. skipping",
      hex::encode(output.id()),
      data.len(),
    );
    return (presumed_origin, None);
  }

  let shorthand = match Shorthand::decode(&mut data) {
    Ok(shorthand) => shorthand,
    Err(e) => {
      log::info!("data in output {} wasn't valid shorthand: {e:?}", hex::encode(output.id()));
      return (presumed_origin, None);
    }
  };
  let instruction = match RefundableInInstruction::try_from(shorthand) {
    Ok(instruction) => instruction,
    Err(e) => {
      log::info!(
        "shorthand in output {} wasn't convertible to a RefundableInInstruction: {e:?}",
        hex::encode(output.id())
      );
      return (presumed_origin, None);
    }
  };

  (
    instruction.origin.and_then(|addr| AddressFor::<S>::try_from(addr).ok()).or(presumed_origin),
    Some(instruction.instruction),
  )
}

pub(crate) struct ScanTask<D: Db, S: ScannerFeed> {
  db: D,
  feed: S,
}

impl<D: Db, S: ScannerFeed> ScanTask<D, S> {
  pub(crate) fn new(mut db: D, feed: S, start_block: u64) -> Self {
    if ScanDb::<S>::next_to_scan_for_outputs_block(&db).is_none() {
      // Initialize the DB
      let mut txn = db.txn();
      ScanDb::<S>::set_next_to_scan_for_outputs_block(&mut txn, start_block);
      txn.commit();
    }

    Self { db, feed }
  }
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for ScanTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    // Fetch the safe to scan block
    let latest_scannable =
      latest_scannable_block::<S>(&self.db).expect("ScanTask run before writing the start block");
    // Fetch the next block to scan
    let next_to_scan = ScanDb::<S>::next_to_scan_for_outputs_block(&self.db)
      .expect("ScanTask run before writing the start block");

    for b in next_to_scan ..= latest_scannable {
      let block = self.feed.block_by_number(&self.db, b).await?;

      log::info!("scanning block: {} ({b})", hex::encode(block.id()));

      let mut txn = self.db.txn();

      assert_eq!(ScanDb::<S>::next_to_scan_for_outputs_block(&txn).unwrap(), b);

      // Tidy the keys, then fetch them
      // We don't have to tidy them here, we just have to somewhere, so why not here?
      ScannerGlobalDb::<S>::tidy_keys(&mut txn);
      let keys = ScannerGlobalDb::<S>::active_keys_as_of_next_to_scan_for_outputs_block(&txn)
        .expect("scanning for a blockchain without any keys set");

      // The scan data for this block
      let mut scan_data = SenderScanData {
        block_number: b,
        received_external_outputs: vec![],
        forwards: vec![],
        returns: vec![],
      };
      // The InInstructions for this block
      let mut in_instructions = vec![];

      // The outputs queued for this block
      let queued_outputs = {
        let mut queued_outputs = ScanDb::<S>::take_queued_outputs(&mut txn, b);
        // Sort the queued outputs in case they weren't queued in a deterministic fashion
        queued_outputs.sort_by(|a, b| sort_outputs(&a.output, &b.output));
        queued_outputs
      };
      for queued_output in queued_outputs {
        in_instructions.push((
          queued_output.output.id(),
          Returnable {
            return_address: queued_output.return_address,
            in_instruction: queued_output.in_instruction,
          },
        ));
        scan_data.received_external_outputs.push(queued_output.output);
      }

      // We subtract the cost to aggregate from some outputs we scan
      // This cost is fetched with an asynchronous function which may be non-trivial
      // We cache the result of this function here to avoid calling it multiple times
      let mut costs_to_aggregate = HashMap::with_capacity(1);

      // Scan for each key
      for key in keys {
        for output in block.scan_for_outputs(key.key) {
          assert_eq!(output.key(), key.key);

          /*
            The scan task runs ahead of time, obtaining ordering on the external network's blocks
            with relation to events on the Serai network. This is done via publishing a Batch which
            contains the InInstructions from External outputs. Accordingly, the scan process only
            has to yield External outputs.

            It'd appear to make sense to scan for all outputs, and after scanning for all outputs,
            yield all outputs. The issue is we can't identify outputs we created here. We can only
            identify the outputs we receive and their *declared intention*.

            We only want to handle Change/Branch/Forwarded outputs we made ourselves. For
            Forwarded, the reasoning is obvious (retiring multisigs should only downsize, yet
            accepting new outputs solely because they claim to be Forwarded would increase the size
            of the multisig). For Change/Branch, it's because such outputs which aren't ours are
            pointless. They wouldn't hurt to accumulate though.

            The issue is they would hurt to accumulate. We want to filter outputs which are less
            than their cost to aggregate, a variable itself variable to the current blockchain. We
            can filter such outputs here, yet if we drop a Change output, we create an insolvency.
            We'd need to track the loss and offset it later. That means we can't filter such
            outputs, as we expect any Change output we make.

            The issue is the Change outputs we don't make. Someone can create an output declaring
            to be Change, yet not actually Change. If we don't filter it, it'd be queued for
            accumulation, yet it may cost more to accumulate than it's worth.

            The solution is to let the Eventuality task, which does know if we made an output or
            not (or rather, if a transaction is identical to a transaction which should exist
            regarding effects) decide to keep/yield the outputs which we should only keep if we
            made them (as Serai itself should not make worthless outputs, so we can assume they're
            worthwhile, and even if they're not economically, they are technically).

            The alternative, we drop outputs here with a generic filter rule and then report back
            the insolvency created, still doesn't work as we'd only be creating an insolvency if
            the output was actually made by us (and not simply someone else sending in). We can
            have the Eventuality task report the insolvency, yet that requires the scanner be
            responsible for such filter logic. It's more flexible, and has a cleaner API,
            to do so at a higher level.
          */
          if output.kind() != OutputType::External {
            // While we don't report these outputs, we still need consensus on this block and
            // accordingly still need to set it as notable
            let balance = output.balance();
            // We ensure it's over the dust limit to prevent people sending 1 satoshi from causing
            // an invocation of a consensus/signing protocol
            if balance.amount.0 >= S::dust(balance.coin).0 {
              ScannerGlobalDb::<S>::flag_notable_due_to_non_external_output(&mut txn, b);
            }
            continue;
          }

          // Check this isn't dust
          let balance_to_use = {
            let mut balance = output.balance();

            // First, subtract 2 * the cost to aggregate, as detailed in
            // `spec/processor/UTXO Management.md`

            // We cache this, so if it isn't yet cached, insert it into the cache
            if let std::collections::hash_map::Entry::Vacant(e) =
              costs_to_aggregate.entry(balance.coin)
            {
              e.insert(self.feed.cost_to_aggregate(balance.coin, &block).await.map_err(|e| {
                format!(
                  "ScanTask couldn't fetch cost to aggregate {:?} at {b}: {e:?}",
                  balance.coin
                )
              })?);
            }
            let cost_to_aggregate = costs_to_aggregate[&balance.coin];
            balance.amount.0 -= 2 * cost_to_aggregate.0;

            // Now, check it's still past the dust threshold
            if balance.amount.0 < S::dust(balance.coin).0 {
              continue;
            }

            balance
          };

          // Fetch the InInstruction/return addr for this output
          let output_with_in_instruction = match in_instruction_from_output::<S>(&output) {
            (return_address, Some(instruction)) => OutputWithInInstruction {
              output,
              return_address,
              in_instruction: InInstructionWithBalance { instruction, balance: balance_to_use },
            },
            (Some(address), None) => {
              // Since there was no instruction here, return this since we parsed a return address
              if key.stage != LifetimeStage::Finishing {
                scan_data.returns.push(Return { address, output });
              }
              continue;
            }
            // Since we didn't receive an instruction nor can we return this, queue this for
            // accumulation and move on
            (None, None) => {
              if key.stage != LifetimeStage::Finishing {
                scan_data.received_external_outputs.push(output);
              }
              continue;
            }
          };

          // Drop External outputs if they're to a multisig which won't report them
          // This means we should report any External output we save to disk here
          #[allow(clippy::match_same_arms)]
          match key.stage {
            // This multisig isn't yet reporting its External outputs to avoid a DoS
            // Queue the output to be reported when this multisig starts reporting
            LifetimeStage::ActiveYetNotReporting => {
              ScanDb::<S>::queue_output_until_block(
                &mut txn,
                key.block_at_which_reporting_starts,
                &output_with_in_instruction,
              );
              continue;
            }
            // We should report External outputs in these cases
            LifetimeStage::Active | LifetimeStage::UsingNewForChange => {}
            // We should report External outputs only once forwarded, where they'll appear as
            // OutputType::Forwarded. We save them now for when they appear
            LifetimeStage::Forwarding => {
              // When the forwarded output appears, we can see which Plan it's associated with and
              // from there recover this output
              scan_data.forwards.push(output_with_in_instruction);
              continue;
            }
            // We should drop these as we should not be handling new External outputs at this
            // time
            LifetimeStage::Finishing => {
              continue;
            }
          }
          // Ensures we didn't miss a `continue` above
          assert!(matches!(key.stage, LifetimeStage::Active | LifetimeStage::UsingNewForChange));

          in_instructions.push((
            output_with_in_instruction.output.id(),
            Returnable {
              return_address: output_with_in_instruction.return_address,
              in_instruction: output_with_in_instruction.in_instruction,
            },
          ));
          scan_data.received_external_outputs.push(output_with_in_instruction.output);
        }
      }

      // Sort the InInstructions by the output ID
      in_instructions.sort_by(|(output_id_a, _), (output_id_b, _)| {
        use core::cmp::{Ordering, Ord};
        let res = output_id_a.as_ref().cmp(output_id_b.as_ref());
        assert!(res != Ordering::Equal, "two outputs within a collection had the same ID");
        res
      });
      // Check we haven't prior reported an InInstruction for this output
      // This is a sanity check which is intended to prevent multiple instances of sriXYZ on-chain
      // due to a single output
      for (id, _) in &in_instructions {
        assert!(
          !ScanDb::<S>::prior_reported_in_instruction_for_output(&txn, id),
          "prior reported an InInstruction for an output with this ID"
        );
        ScanDb::<S>::reported_in_instruction_for_output(&mut txn, id);
      }
      // Reformat the InInstructions to just the InInstructions
      let in_instructions =
        in_instructions.into_iter().map(|(_id, in_instruction)| in_instruction).collect::<Vec<_>>();
      // Send the InInstructions to the report task
      ScanToReportDb::<S>::send_in_instructions(&mut txn, b, &in_instructions);

      // Send the scan data to the eventuality task
      ScanToEventualityDb::<S>::send_scan_data(&mut txn, b, &scan_data);
      // Update the next to scan block
      ScanDb::<S>::set_next_to_scan_for_outputs_block(&mut txn, b + 1);
      txn.commit();
    }

    // Run dependents if we successfully scanned any blocks
    Ok(next_to_scan <= latest_scannable)
  }
}
