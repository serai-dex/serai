use std::collections::{HashSet, HashMap};

use group::GroupEncoding;

use serai_db::{Get, DbTxn, Db};

use primitives::{task::ContinuallyRan, OutputType, ReceivedOutput, Eventuality, Block, Payment};

use crate::{
  lifetime::LifetimeStage,
  db::{
    SeraiKey, OutputWithInInstruction, ReceiverScanData, ScannerGlobalDb, SubstrateToEventualityDb,
    ScanToEventualityDb,
  },
  BlockExt, ScannerFeed, KeyFor, AddressFor, OutputFor, EventualityFor, SchedulerUpdate, Scheduler,
  sort_outputs,
  scan::{next_to_scan_for_outputs_block, queue_output_until_block},
};

mod db;
use db::EventualityDb;

/// The latest scannable block, which is determined by this task.
///
/// This task decides when a key retires, which impacts the scan task. Accordingly, the scanner is
/// only allowed to scan `S::WINDOW_LENGTH - 1` blocks ahead so we can safely schedule keys to
/// retire `S::WINDOW_LENGTH` blocks out.
pub(crate) fn latest_scannable_block<S: ScannerFeed>(getter: &impl Get) -> Option<u64> {
  assert!(S::WINDOW_LENGTH > 0);
  EventualityDb::<S>::next_to_check_for_eventualities_block(getter)
    .map(|b| b + S::WINDOW_LENGTH - 1)
}

/// Intake a set of Eventualities into the DB.
///
/// The HashMap is keyed by the key these Eventualities are for.
fn intake_eventualities<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  to_intake: HashMap<Vec<u8>, Vec<EventualityFor<S>>>,
) {
  for (key, new_eventualities) in to_intake {
    let key = {
      let mut key_repr = <KeyFor<S> as GroupEncoding>::Repr::default();
      assert_eq!(key.len(), key_repr.as_ref().len());
      key_repr.as_mut().copy_from_slice(&key);
      KeyFor::<S>::from_bytes(&key_repr).unwrap()
    };

    let mut eventualities = EventualityDb::<S>::eventualities(txn, key);
    for new_eventuality in new_eventualities {
      eventualities.insert(new_eventuality);
    }
    EventualityDb::<S>::set_eventualities(txn, key, &eventualities);
  }
}

/*
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
pub(crate) struct EventualityTask<D: Db, S: ScannerFeed, Sch: Scheduler<S>> {
  db: D,
  feed: S,
  scheduler: Sch,
}

impl<D: Db, S: ScannerFeed, Sch: Scheduler<S>> EventualityTask<D, S, Sch> {
  pub(crate) fn new(mut db: D, feed: S, scheduler: Sch, start_block: u64) -> Self {
    if EventualityDb::<S>::next_to_check_for_eventualities_block(&db).is_none() {
      // Initialize the DB
      let mut txn = db.txn();
      EventualityDb::<S>::set_next_to_check_for_eventualities_block(&mut txn, start_block);
      txn.commit();
    }

    Self { db, feed, scheduler }
  }

  #[allow(clippy::type_complexity)]
  fn keys_and_keys_with_stages(
    &self,
    block_number: u64,
  ) -> (Vec<SeraiKey<KeyFor<S>>>, Vec<(KeyFor<S>, LifetimeStage)>) {
    /*
      This is proper as the keys for the next-to-scan block (at most `WINDOW_LENGTH` ahead,
      which is `<= CONFIRMATIONS`) will be the keys to use here, with only minor edge cases.

      This may include a key which has yet to activate by our perception. We can simply drop
      those.

      This may not include a key which has retired by the next-to-scan block. This task is the
      one which decides when to retire a key, and when it marks a key to be retired, it is done
      with it. Accordingly, it's not an issue if such a key was dropped.

      This also may include a key we've retired which has yet to officially retire. That's fine as
      we'll do nothing with it, and the Scheduler traits document this behavior.
    */
    assert!(S::WINDOW_LENGTH <= S::CONFIRMATIONS);
    let mut keys = ScannerGlobalDb::<S>::active_keys_as_of_next_to_scan_for_outputs_block(&self.db)
      .expect("scanning for a blockchain without any keys set");
    // Since the next-to-scan block is ahead of us, drop keys which have yet to actually activate
    keys.retain(|key| block_number <= key.activation_block_number);
    let keys_with_stages = keys.iter().map(|key| (key.key, key.stage)).collect::<Vec<_>>();

    (keys, keys_with_stages)
  }

  // Returns a boolean of if we intaked any Burns.
  fn intake_burns(&mut self) -> bool {
    let mut intaked_any = false;

    // If we've handled an notable block, we may have Burns being queued with it as the reference
    if let Some(latest_handled_notable_block) =
      EventualityDb::<S>::latest_handled_notable_block(&self.db)
    {
      // We always intake Burns per this block as it's the block we have consensus on
      // We would have a consensus failure if some thought the change should be the old key and
      // others the new key
      let (_keys, keys_with_stages) = self.keys_and_keys_with_stages(latest_handled_notable_block);

      let mut txn = self.db.txn();
      // Drain the entire channel
      while let Some(burns) =
        SubstrateToEventualityDb::try_recv_burns(&mut txn, latest_handled_notable_block)
      {
        intaked_any = true;

        let new_eventualities = self.scheduler.fulfill(
          &mut txn,
          &keys_with_stages,
          burns
            .into_iter()
            .filter_map(|burn| Payment::<AddressFor<S>>::try_from(burn).ok())
            .collect(),
        );
        intake_eventualities::<S>(&mut txn, new_eventualities);
      }
      txn.commit();
    }

    intaked_any
  }
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed, Sch: Scheduler<S>> ContinuallyRan for EventualityTask<D, S, Sch> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    // Fetch the highest acknowledged block
    let Some(highest_acknowledged) = ScannerGlobalDb::<S>::highest_acknowledged_block(&self.db)
    else {
      // If we've never acknowledged a block, return
      return Ok(false);
    };

    // A boolean of if we've made any progress to return at the end of the function
    let mut made_progress = false;

    // Start by intaking any Burns we have sitting around
    // It's important we run this regardless of if we have a new block to handle
    made_progress |= self.intake_burns();

    /*
      Eventualities increase upon one of two cases:

        1) We're fulfilling Burns
        2) We acknowledged a block

      We can't know the processor has intaked all Burns it should have when we process block `b`.
      We solve this by executing a consensus protocol whenever a resolution for an Eventuality
      created to fulfill Burns occurs. Accordingly, we force ourselves to obtain synchrony on such
      blocks (and all preceding Burns).

      This means we can only iterate up to the block currently pending acknowledgement.

      We only know blocks will need acknowledgement *for sure* if they were scanned. The only other
      causes are key activation and retirement (both scheduled outside the scan window). This makes
      the exclusive upper bound the *next block to scan*.
    */
    let exclusive_upper_bound = {
      // Fetch the next to scan block
      let next_to_scan = next_to_scan_for_outputs_block::<S>(&self.db)
        .expect("EventualityTask run before writing the start block");
      // If we haven't done any work, return
      if next_to_scan == 0 {
        return Ok(false);
      }
      next_to_scan
    };

    // Fetch the next block to check
    let next_to_check = EventualityDb::<S>::next_to_check_for_eventualities_block(&self.db)
      .expect("EventualityTask run before writing the start block");

    // Check all blocks
    for b in next_to_check .. exclusive_upper_bound {
      let is_block_notable = ScannerGlobalDb::<S>::is_block_notable(&self.db, b);
      if is_block_notable {
        /*
          If this block is notable *and* not acknowledged, break.

          This is so if Burns queued prior to this block's acknowledgement caused any Eventualities
          (which may resolve this block), we have them. If it wasn't for that, it'd be so if this
          block's acknowledgement caused any Eventualities, we have them, though those would only
          potentially resolve in the next block (letting us scan this block without delay).
        */
        if b > highest_acknowledged {
          break;
        }

        // Since this block is notable, ensure we've intaked all the Burns preceding it
        // We can know with certainty that the channel is fully populated at this time since we've
        // acknowledged a newer block (so we've handled the state up to this point and any new
        // state will be for the newer block)
        #[allow(unused_assignments)]
        {
          made_progress |= self.intake_burns();
        }
      }

      // Since we're handling this block, we are making progress
      made_progress = true;

      let block = self.feed.block_by_number(&self.db, b).await?;

      log::debug!("checking eventuality completions in block: {} ({b})", hex::encode(block.id()));

      let (keys, keys_with_stages) = self.keys_and_keys_with_stages(b);

      let mut txn = self.db.txn();

      // Fetch the data from the scanner
      let scan_data = ScanToEventualityDb::recv_scan_data(&mut txn, b);
      assert_eq!(scan_data.block_number, b);
      let ReceiverScanData { block_number: _, received_external_outputs, forwards, returns } =
        scan_data;
      let mut outputs = received_external_outputs;

      for key in &keys {
        // If this is the key's activation block, activate it
        if key.activation_block_number == b {
          self.scheduler.activate_key(&mut txn, key.key);
        }

        let completed_eventualities = {
          let mut eventualities = EventualityDb::<S>::eventualities(&txn, key.key);
          let completed_eventualities = block.check_for_eventuality_resolutions(&mut eventualities);
          EventualityDb::<S>::set_eventualities(&mut txn, key.key, &eventualities);
          completed_eventualities
        };

        for tx in completed_eventualities.keys() {
          log::info!("eventuality resolved by {}", hex::encode(tx.as_ref()));
        }

        // Fetch all non-External outputs
        let mut non_external_outputs = block.scan_for_outputs(key.key);
        non_external_outputs.retain(|output| output.kind() != OutputType::External);
        // Drop any outputs less than the dust limit
        non_external_outputs.retain(|output| {
          let balance = output.balance();
          balance.amount.0 >= S::dust(balance.coin).0
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

        // Finally, for non-External outputs we didn't make, we check they're worth more than the
        // cost to aggregate them to avoid some profitable spam attacks by malicious miners
        {
          // Fetch and cache the costs to aggregate as this call may be expensive
          let coins =
            non_external_outputs.iter().map(|output| output.balance().coin).collect::<HashSet<_>>();
          let mut costs_to_aggregate = HashMap::new();
          for coin in coins {
            costs_to_aggregate.insert(
              coin,
              self.feed.cost_to_aggregate(coin, &block).await.map_err(|e| {
                format!("EventualityTask couldn't fetch cost to aggregate {coin:?} at {b}: {e:?}")
              })?,
            );
          }

          // Only retain out outputs/outputs sufficiently worthwhile
          non_external_outputs.retain(|output| {
            completed_eventualities.contains_key(&output.transaction_id()) || {
              let balance = output.balance();
              balance.amount.0 >= (2 * costs_to_aggregate[&balance.coin].0)
            }
          });
        }

        // Now, we iterate over all Forwarded outputs and queue their InInstructions
        for output in
          non_external_outputs.iter().filter(|output| output.kind() == OutputType::Forwarded)
        {
          let Some(eventuality) = completed_eventualities.get(&output.transaction_id()) else {
            // Output sent to the forwarding address yet not one we made
            continue;
          };
          let Some(forwarded) = eventuality.singular_spent_output() else {
            // This was a TX made by us, yet someone burned to the forwarding address as it doesn't
            // follow the structure of forwarding transactions
            continue;
          };

          let Some((return_address, mut in_instruction)) =
            ScannerGlobalDb::<S>::return_address_and_in_instruction_for_forwarded_output(
              &txn, &forwarded,
            )
          else {
            // This was a TX made by us, coincidentally with the necessary structure, yet wasn't
            // forwarding an output
            continue;
          };

          // We use the original amount, minus twice the cost to aggregate
          // If the fees we paid to forward this now (less than the cost to aggregate now, yet not
          // necessarily the cost to aggregate historically) caused this amount to be less, reduce
          // it accordingly
          in_instruction.balance.amount.0 =
            in_instruction.balance.amount.0.min(output.balance().amount.0);

          queue_output_until_block::<S>(
            &mut txn,
            b + S::WINDOW_LENGTH,
            &OutputWithInInstruction { output: output.clone(), return_address, in_instruction },
          );
        }

        // Accumulate all of these outputs
        outputs.extend(non_external_outputs);
      }

      // Update the scheduler
      {
        let mut scheduler_update = SchedulerUpdate { outputs, forwards, returns };
        scheduler_update.outputs.sort_by(sort_outputs);
        scheduler_update.forwards.sort_by(sort_outputs);
        scheduler_update.returns.sort_by(|a, b| sort_outputs(&a.output, &b.output));

        let empty = {
          let a: core::slice::Iter<'_, OutputFor<S>> = scheduler_update.outputs.iter();
          let b: core::slice::Iter<'_, OutputFor<S>> = scheduler_update.forwards.iter();
          let c = scheduler_update.returns.iter().map(|output_to_return| &output_to_return.output);
          let mut all_outputs = a.chain(b).chain(c).peekable();

          // If we received any output, sanity check this block is notable
          let empty = all_outputs.peek().is_none();
          if !empty {
            assert!(is_block_notable, "accumulating output(s) in non-notable block");
          }

          // Sanity check we've never accumulated these outputs before
          for output in all_outputs {
            assert!(
              !EventualityDb::<S>::prior_accumulated_output(&txn, &output.id()),
              "prior accumulated an output with this ID"
            );
            EventualityDb::<S>::accumulated_output(&mut txn, &output.id());
          }

          empty
        };

        if !empty {
          // Accumulate the outputs
          /*
            This uses the `keys_with_stages` for the current block, yet this block is notable.
            Accordingly, all future intaked Burns will use at least this block when determining
            what LifetimeStage a key is. That makes the LifetimeStage monotonically incremented. If
            this block wasn't notable, we'd potentially intake Burns with the LifetimeStage
            determined off an earlier block than this (enabling an earlier LifetimeStage to be used
            after a later one was already used).
          */
          let new_eventualities =
            self.scheduler.update(&mut txn, &keys_with_stages, scheduler_update);
          // Intake the new Eventualities
          for key in new_eventualities.keys() {
            keys
              .iter()
              .find(|serai_key| serai_key.key.to_bytes().as_ref() == key.as_slice())
              .expect("intaking Eventuality for key which isn't active");
          }
          intake_eventualities::<S>(&mut txn, new_eventualities);
        }
      }

      for key in &keys {
        // If this is the block at which forwarding starts for this key, flush it
        // We do this after we issue the above update for any efficiencies gained by doing so
        if key.block_at_which_forwarding_starts == Some(b) {
          assert!(
            key.key != keys.last().unwrap().key,
            "key which was forwarding was the last key (which has no key after it to forward to)"
          );
          self.scheduler.flush_key(&mut txn, key.key, keys.last().unwrap().key);
        }

        // Now that we've intaked any Eventualities caused, check if we're retiring any keys
        if key.stage == LifetimeStage::Finishing {
          let eventualities = EventualityDb::<S>::eventualities(&txn, key.key);
          if eventualities.active_eventualities.is_empty() {
            log::info!(
              "key {} has finished and is being retired",
              hex::encode(key.key.to_bytes().as_ref())
            );

            // Retire this key `WINDOW_LENGTH` blocks in the future to ensure the scan task never
            // has a malleable view of the keys.
            ScannerGlobalDb::<S>::retire_key(&mut txn, b + S::WINDOW_LENGTH, key.key);

            // We tell the scheduler to retire it now as we're done with it, and this fn doesn't
            // require it be called with a canonical order
            self.scheduler.retire_key(&mut txn, key.key);
          }
        }
      }

      // Update the next-to-check block
      EventualityDb::<S>::set_next_to_check_for_eventualities_block(&mut txn, next_to_check);

      // If this block was notable, update the latest-handled notable block
      if is_block_notable {
        EventualityDb::<S>::set_latest_handled_notable_block(&mut txn, b);
      }

      txn.commit();
    }

    // Run dependents if we successfully checked any blocks
    Ok(made_progress)
  }
}
