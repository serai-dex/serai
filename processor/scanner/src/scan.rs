use scale::Decode;
use serai_db::{DbTxn, Db};

use serai_primitives::MAX_DATA_LEN;
use serai_in_instructions_primitives::{
  Shorthand, RefundableInInstruction, InInstruction, InInstructionWithBalance,
};

use primitives::{task::ContinuallyRan, OutputType, ReceivedOutput, Block};

// TODO: Localize to ScanDb?
use crate::{
  lifetime::LifetimeStage,
  db::{OutputWithInInstruction, SenderScanData, ScannerDb, ScanToReportDb, ScanToEventualityDb},
  BlockExt, ScannerFeed, AddressFor, OutputFor, Return, sort_outputs,
};

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
      let block = self.feed.block_by_number(&self.db, b).await?;

      log::info!("scanning block: {} ({b})", hex::encode(block.id()));

      assert_eq!(ScannerDb::<S>::next_to_scan_for_outputs_block(&self.db).unwrap(), b);
      let keys = ScannerDb::<S>::active_keys_as_of_next_to_scan_for_outputs_block(&self.db)
        .expect("scanning for a blockchain without any keys set");

      let mut txn = self.db.txn();

      let mut scan_data = SenderScanData {
        block_number: b,
        received_external_outputs: vec![],
        forwards: vec![],
        returns: vec![],
      };
      let mut in_instructions = vec![];

      let queued_outputs = {
        let mut queued_outputs = ScannerDb::<S>::take_queued_outputs(&mut txn, b);
        // Sort the queued outputs in case they weren't queued in a deterministic fashion
        queued_outputs.sort_by(|a, b| sort_outputs(&a.output, &b.output));
        queued_outputs
      };
      for queued_output in queued_outputs {
        scan_data.received_external_outputs.push(queued_output.output);
        in_instructions.push(queued_output.in_instruction);
      }

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
            if balance.amount.0 >= self.feed.dust(balance.coin).0 {
              ScannerDb::<S>::flag_notable(&mut txn, b);
            }
            continue;
          }

          // Check this isn't dust
          let balance_to_use = {
            let mut balance = output.balance();
            // First, subtract 2 * the cost to aggregate, as detailed in
            // `spec/processor/UTXO Management.md`
            // TODO: Cache this
            let cost_to_aggregate =
              self.feed.cost_to_aggregate(balance.coin, b).await.map_err(|e| {
                format!("couldn't fetch cost to aggregate {:?} at {b}: {e:?}", balance.coin)
              })?;
            balance.amount.0 -= 2 * cost_to_aggregate.0;

            // Now, check it's still past the dust threshold
            if balance.amount.0 < self.feed.dust(balance.coin).0 {
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
              ScannerDb::<S>::queue_output_until_block(
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

          scan_data.received_external_outputs.push(output_with_in_instruction.output.clone());
          in_instructions.push(output_with_in_instruction.in_instruction);
        }
      }

      // Send the scan data to the eventuality task
      ScanToEventualityDb::<S>::send_scan_data(&mut txn, b, &scan_data);
      // Send the InInstructions to the report task
      ScanToReportDb::<S>::send_in_instructions(&mut txn, b, in_instructions);
      // Update the next to scan block
      ScannerDb::<S>::set_next_to_scan_for_outputs_block(&mut txn, b + 1);
      txn.commit();
    }

    // Run dependents if we successfully scanned any blocks
    Ok(next_to_scan <= latest_scannable)
  }
}
