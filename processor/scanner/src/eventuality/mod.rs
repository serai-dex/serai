use core::future::Future;
use std::collections::{HashSet, HashMap};

use group::GroupEncoding;

use serai_db::{Get, Transaction as DbTxn, Db};

use primitives::{
  task::ContinuallyRan, OutputType, ReceivedOutput as _, EncodableG, Eventuality as _, Block as _,
  Payment,
};

use crate::{
  lifetime::LifetimeStage,
  db::{
    SeraiKey, OutputWithInInstruction, ReceiverScanData, RetireAt, ScannerGlobalDb,
    SubstrateToEventualityDb, ScanToEventualityDb,
  },
  BlockExt as _, ScannerFeed, KeyFor, AddressFor, OutputFor, EventualityFor, SchedulerUpdate,
  Scheduler, CompletedEventualities, sort_outputs,
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
pub(crate) struct EventualityTask<D: 'static + Send + Sync, S: ScannerFeed, Sch: Scheduler<S>> {
  db: D,
  feed: S,
  scheduler: Sch,
}

impl<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  S: ScannerFeed,
  Sch: Scheduler<S>,
> EventualityTask<D, S, Sch>
{
  pub(crate) fn new(mut db: D, feed: S, scheduler: Sch, start_block: u64) -> Self {
    if EventualityDb::<S>::next_to_check_for_eventualities_block(&db).is_none() {
      // Initialize the DB
      let mut txn = db.txn();
      EventualityDb::<S>::set_next_to_check_for_eventualities_block(&mut txn, start_block);
      txn.commit();
    }

    Self { db, feed, scheduler }
  }

  #[expect(clippy::type_complexity)]
  fn keys_and_keys_with_stages(
    &self,
    block_number: u64,
  ) -> (Vec<SeraiKey<KeyFor<S>>>, Vec<(KeyFor<S>, LifetimeStage)>) {
    /*
      We use the block number that the eventuality task is currently handling here
      to ensure that all validators are using the same set of keys at the same stage.
    */
    let keys = ScannerGlobalDb::<S>::active_keys(&self.db, block_number)
      .expect("scanning for a blockchain without any keys set");
    assert!(keys.iter().all(|key| key.activation_block_number <= block_number));
    let keys_with_stages = keys.iter().map(|key| (key.key, key.stage)).collect::<Vec<_>>();

    (keys, keys_with_stages)
  }

  // Returns a boolean of if we intaked any Burns.
  async fn intake_burns(&mut self) -> Result<bool, String> {
    let mut intaked_any = false;

    // If we've handled an notable block, we may have Burns being queued with it as the reference
    if let Some(latest_handled_notable_block) =
      EventualityDb::<S>::latest_handled_notable_block(&self.db)
    {
      // We always intake Burns per this block as it's the block we have consensus on
      // We would have a consensus failure if some thought the change should be the old key and
      // others the new key
      let (_keys, keys_with_stages) = self.keys_and_keys_with_stages(latest_handled_notable_block);

      let block = self.feed.block_by_number(&self.db, latest_handled_notable_block).await?;

      let mut txn = self.db.txn();
      // Drain the entire channel
      while let Some(burns) =
        SubstrateToEventualityDb::try_recv_burns(&mut txn, latest_handled_notable_block)
      {
        intaked_any = true;

        let new_eventualities = self
          .scheduler
          .fulfill(
            &mut txn,
            &block,
            &keys_with_stages,
            burns
              .into_iter()
              .filter_map(|burn| Payment::<AddressFor<S>>::try_from(burn).ok())
              .collect(),
          )
          .await
          .map_err(|e| format!("failed to queue fulfilling payments: {e:?}"))?;
        intake_eventualities::<S>(&mut txn, new_eventualities);
      }
      txn.commit();
    }

    Ok(intaked_any)
  }
}

impl<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  S: ScannerFeed,
  Sch: Scheduler<S>,
> ContinuallyRan for EventualityTask<D, S, Sch>
{
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
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
      made_progress |= self.intake_burns().await?;

      /*
        Eventualities increase upon one of two cases:

          1) We're fulfilling Burns
          2) We acknowledged a block

        We can't know the processor has intaked all Burns it should have when we process block `b`.
        We solve this by executing a consensus protocol whenever a resolution for an Eventuality
        created to fulfill Burns occurs. Accordingly, we force ourselves to obtain synchrony on
        such blocks (and all preceding Burns).

        This means we can only iterate up to the block currently pending acknowledgement.

        We only know blocks will need acknowledgement *for sure* if they were scanned. The only
        other causes are key activation and retirement (both scheduled outside the scan window).
        This makes the exclusive upper bound the *next block to scan*.
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

            This is so if Burns queued prior to this block's acknowledgement caused any
            Eventualities (which may resolve this block), we have them. If it wasn't for that, it'd
            be so if this block's acknowledgement caused any Eventualities, we have them, though
            those would only potentially resolve in the next block (letting us scan this block
            without delay).
          */
          if b > highest_acknowledged {
            break;
          }

          // Since this block is notable, ensure we've intaked all the Burns preceding it
          // We can know with certainty that the channel is fully populated at this time since
          // we've acknowledged a newer block (so we've handled the state up to this point and any
          // new state will be for the newer block)
          #[expect(unused_assignments)]
          {
            made_progress |= self.intake_burns().await?;
          }
        }

        // Since we're handling this block, we are making progress
        made_progress = true;

        let block = self.feed.block_by_number(&self.db, b).await?;

        log::debug!("checking eventuality completions in block: {} ({b})", hex::encode(block.id()));

        let (keys, keys_with_stages) = self.keys_and_keys_with_stages(b);
        let latest_active_key = {
          let mut keys_with_stages = keys_with_stages.clone();
          let most_recent_key =
            keys_with_stages.last().expect("checking eventualities with no active keys").0;
          loop {
            // Use the most recent key
            let Some((key, stage)) = keys_with_stages.pop() else { break most_recent_key };
            // Unless this key is active, but not yet reporting
            if stage == LifetimeStage::ActiveYetNotReporting {
              continue;
            }
            break key;
          }
        };

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
            Sch::activate_key(&mut txn, key.key);
          }

          let completed_eventualities = {
            let mut eventualities = EventualityDb::<S>::eventualities(&txn, key.key);
            let completed_eventualities =
              block.check_for_eventuality_resolutions(&mut eventualities);
            EventualityDb::<S>::set_eventualities(&mut txn, key.key, &eventualities);
            completed_eventualities
          };

          for (tx, eventuality) in &completed_eventualities {
            log::info!(
              "eventuality {} resolved by {}",
              hex::encode(eventuality.id()),
              hex::encode(tx.as_ref())
            );
            CompletedEventualities::send(&mut txn, &key.key, eventuality.id());
          }

          // Fetch all non-External outputs
          let mut non_external_outputs = block.scan_for_outputs(latest_active_key, key.key);
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

            The commentary on Change outputs also applies to Branch/Forwarded. They'll presumably
            get ignored if not usable however.
          */
          if key.stage == LifetimeStage::Finishing {
            non_external_outputs
              .retain(|output| completed_eventualities.contains_key(&output.transaction_id()));
          }

          // Finally, for non-External outputs we didn't make, we check they're worth more than the
          // cost to aggregate them to avoid some profitable spam attacks by malicious miners
          {
            // Fetch and cache the costs to aggregate as this call may be expensive
            let coins = non_external_outputs
              .iter()
              .map(|output| output.balance().coin)
              .collect::<HashSet<_>>();
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
              // This was a TX made by us, yet someone burned to the forwarding address as it
              // doesn't follow the structure of forwarding transactions
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
            let c =
              scheduler_update.returns.iter().map(|output_to_return| &output_to_return.output);
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
              what LifetimeStage a key is. That makes the LifetimeStage monotonically incremented.
              If this block wasn't notable, we'd potentially intake Burns with the LifetimeStage
              determined off an earlier block than this (enabling an earlier LifetimeStage to be
              used after a later one was already used).
            */
            let new_eventualities = self
              .scheduler
              .update(&mut txn, &block, &keys_with_stages, scheduler_update)
              .await
              .map_err(|e| format!("failed to update scheduler: {e:?}"))?;
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
            let new_eventualities = self
              .scheduler
              .flush_key(&mut txn, &block, key.key, keys.last().unwrap().key)
              .await
              .map_err(|e| format!("failed to flush key from scheduler: {e:?}"))?;
            intake_eventualities::<S>(&mut txn, new_eventualities);
          }

          // Now that we've intaked any Eventualities caused, check if we're retiring any keys
          if key.stage == LifetimeStage::Finishing &&
            RetireAt::get(&txn, EncodableG(key.key)).is_none()
          {
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
              Sch::retire_key(&mut txn, key.key);
            }
          }
        }

        // Update the next-to-check block
        EventualityDb::<S>::set_next_to_check_for_eventualities_block(&mut txn, b + 1);

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
}

/// Generic tests for the eventuality task. These should be plug-and-play with an implemented
/// ScannerFeed.
#[cfg(feature = "tests")]
pub mod eventuality_tests {
  use primitives::{EncodableG, task::ContinuallyRan as _};
  use serai_db::{new_rocksdb, Db, Transaction as _};
  use tempfile::TempDir;

  use crate::{
    DaemonHelper,
    db::RetireAt,
    ScannerFeed, ScannerGlobalDb,
    eventuality::{EventualityTask, EventualityDb},
    index::IndexTask,
    KeyFor,
    lifetime::{Lifetime, LifetimeStage},
    scan::{next_to_scan_for_outputs_block, ScanTask},
    Scheduler,
  };

  async fn init_tasks<
    D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
    S: ScannerFeed,
    Sch: Scheduler<S>,
  >(
    db: D,
    feed: S,
    scheduler: Sch,
    start_block: u64,
  ) -> (IndexTask<D, S>, ScanTask<D, S>, EventualityTask<D, S, Sch>) {
    // 1. IndexTask
    // The EventualityTask depends on the IndexTask for block_by_number.
    let index_task = IndexTask::new(db.clone(), feed.clone(), start_block).await;
    let res = feed.block_by_number(&db, start_block).await;
    res.unwrap();

    // 2. ScanTask
    // The EventualityTask depends on the ScanTask for next_to_scan_for_outputs_block and
    // recv_scan_data.
    assert!(next_to_scan_for_outputs_block::<S>(&db).is_none());
    let scan_task = ScanTask::new(db.clone(), feed.clone(), start_block);
    assert_eq!(next_to_scan_for_outputs_block::<S>(&db).unwrap(), start_block);

    // 3. EventualityTask
    assert!(EventualityDb::<S>::next_to_check_for_eventualities_block(&db).is_none());
    let eventuality_task =
      EventualityTask::<_, _, _>::new(db.clone(), feed.clone(), scheduler, start_block);
    assert_eq!(
      EventualityDb::<S>::next_to_check_for_eventualities_block(&db).unwrap(),
      start_block
    );

    (index_task, scan_task, eventuality_task)
  }

  async fn init_test<S: ScannerFeed, Sch: Scheduler<S>>(
    feed: S,
    scheduler: Sch,
    start_key: KeyFor<S>,
    next_key: KeyFor<S>,
  ) -> (
    TempDir,
    impl 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
    u64,
    u64,
    IndexTask<impl 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>, S>,
    ScanTask<impl 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>, S>,
    EventualityTask<impl 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>, S, Sch>,
  ) {
    let temp_dir = TempDir::new().unwrap();
    let mut temp_db = new_rocksdb(temp_dir.path().to_str().unwrap());
    let start_block = feed.latest_finalized_block_number().await.unwrap();

    // Initialize the scanner (see Scanner::initialize), but don't start tasks yet.
    // We want to control task iterations manually. This registers the start_key.
    {
      let mut txn = temp_db.txn();
      ScannerGlobalDb::<S>::set_start_block(&mut txn, start_block);
      ScannerGlobalDb::<S>::queue_key(&mut txn, start_block, start_key);
      txn.commit();
    }

    // Initialize IndexTask, ScanTask, and EventualityTask.
    let (index_task, scan_task, eventuality_task) =
      init_tasks(temp_db.clone(), feed.clone(), scheduler, start_block).await;

    // Establish a full lifetime cycle of the start_key.
    let start_key_active_block = Lifetime::active_yet_not_reporting_end_block::<S>(start_block);
    // We need to activate the next_keys once start_key is already active. Then start_key's
    // lifecycle is determined by the activation block of the next key. See inside calculate
    // assert!(next_keys_activation_block_number > active_yet_not_reporting_end_block).
    let next_keys_activation_block_number = start_key_active_block + 1;
    let new_active_yet_not_reporting_end_block =
      Lifetime::active_yet_not_reporting_end_block::<S>(next_keys_activation_block_number);
    let new_active_and_used_for_change_end_block =
      Lifetime::using_for_change_end_block::<S>(new_active_yet_not_reporting_end_block);
    let new_active_and_forwarded_to_end_block =
      Lifetime::forwarding_end_block::<S>(new_active_and_used_for_change_end_block);

    let expected_start_keys_lifetime = Lifetime {
      stage: LifetimeStage::Finishing,
      block_at_which_reporting_starts: start_key_active_block,
      block_at_which_forwarding_starts: Some(new_active_and_used_for_change_end_block),
    };
    let start_keys_lifetime = Lifetime::calculate::<S>(
      new_active_and_forwarded_to_end_block,
      start_block,
      Some(next_keys_activation_block_number),
    );
    assert_eq!(start_keys_lifetime, expected_start_keys_lifetime);

    {
      let mut txn = temp_db.txn();
      // Register the next_key with its activation block number.
      ScannerGlobalDb::<S>::queue_key(&mut txn, next_keys_activation_block_number, next_key);
      // Set the highest acknowledged block to something high to allow the start_key to be retired
      // In the Eventuality Task, see the read for highest_acknowledged_block and later call to
      // retire_key. The highest ack'd block must be set at or past the retirement block to allow
      // the Eventuality Task to handle it.
      let retirement_block = new_active_and_forwarded_to_end_block + S::WINDOW_LENGTH;
      let highest_ackd_block = retirement_block;
      ScannerGlobalDb::<S>::set_highest_acknowledged_block(&mut txn, highest_ackd_block);
      txn.commit();
    }

    (
      temp_dir,
      temp_db,
      start_block,
      new_active_and_forwarded_to_end_block,
      index_task,
      scan_task,
      eventuality_task,
    )
  }

  /// Ensure a key's retirement block is set by the Eventuality Task once the Eventuality
  /// Task handles the key's Finishing block. This ensures the retirement block gets set
  /// to the same value for all validators. This test iterates 1 block at a time around
  /// the key's Finishing block.
  ///
  /// As a bonus, this test also continues advancing the chain and iterating Tasks until
  /// the Eventuality Task handles the retirement block, and ensures state remains as
  /// expected until then.
  async fn deterministic_retirement_advance_one_block_at_a_time<
    S: ScannerFeed,
    D: DaemonHelper,
    Sch: Scheduler<S>,
  >(
    feed: S,
    daemon: D,
    scheduler: Sch,
    start_key: KeyFor<S>,
    next_key: KeyFor<S>,
  ) {
    daemon.reset_chain().await;
    daemon.setup_finalized_block().await;

    let (
      _temp_dir,
      temp_db,
      start_block,
      starting_finishing_block,
      mut index_task,
      mut scan_task,
      mut eventuality_task,
    ) = init_test(feed.clone(), scheduler, start_key, next_key).await;

    // Mine until 2 blocks before start_key enters the Finishing stage.
    // We'll run the tasks up until that block, so we can then control
    // and test expected behavior 1 block at a time.
    let mine_up_to_retire_block = starting_finishing_block - 2;
    let mine_n_blocks_up_to_retire = mine_up_to_retire_block - start_block;
    daemon.add_blocks(mine_n_blocks_up_to_retire.try_into().unwrap()).await;

    let mut run_all_tasks = async || {
      index_task.run_iteration().await.unwrap();
      scan_task.run_iteration().await.unwrap();
      eventuality_task.run_iteration().await.unwrap();
    };

    // Run the tasks until the Eventuality Task has handled right up until retirement.
    let mut next_to_check =
      EventualityDb::<S>::next_to_check_for_eventualities_block(&temp_db).unwrap();
    while next_to_check <= mine_up_to_retire_block {
      run_all_tasks().await;
      let new_next_to_check =
        EventualityDb::<S>::next_to_check_for_eventualities_block(&temp_db).unwrap();
      assert!(new_next_to_check > next_to_check);
      next_to_check = new_next_to_check;
    }
    assert_eq!(next_to_check, starting_finishing_block - 1);

    // We expect:
    //   - start_key to be in the Forwarding stage (it's about to enter Finishing on next block)
    //   - next_key to be activated (it activated once the Eventuality Task handled
    //     next_keys_activation_block_number)
    let activated_keys = ScannerGlobalDb::<S>::active_keys(&temp_db, next_to_check).unwrap();
    assert_eq!(activated_keys.len(), 2);
    let activated_start_key = activated_keys.iter().find(|k| k.key == start_key).unwrap();
    let activated_next_key = activated_keys.iter().find(|k| k.key == next_key).unwrap();
    assert_eq!(activated_start_key.stage, LifetimeStage::Forwarding);
    assert_eq!(activated_next_key.stage, LifetimeStage::Active);

    // Because of the Eventuality Task, we expect that the retirement block
    // is not set yet. We don't expect it to be set until the Eventuality Task
    // handles starting_finishing_block.
    let retire_at = RetireAt::get(&temp_db, EncodableG(start_key));
    assert!(retire_at.is_none());

    // After 1 more iteration, the start_key should be Finishing as of
    // the next block the Eventuality Task will handle, but the retirement
    // block should not be set by the Eventuality Task yet.
    // We don't want the scan state to drive retirement. We want retirement
    // to happen when the Eventuality Task handles starting_finishing_block.
    daemon.add_blocks(1).await;
    run_all_tasks().await;
    next_to_check = EventualityDb::<S>::next_to_check_for_eventualities_block(&temp_db).unwrap();
    assert_eq!(next_to_check, starting_finishing_block);
    let activated_keys = ScannerGlobalDb::<S>::active_keys(&temp_db, next_to_check).unwrap();
    assert_eq!(activated_keys.len(), 2);
      let activated_start_key = activated_keys.iter().find(|k| k.key == start_key).unwrap();
    let activated_next_key = activated_keys.iter().find(|k| k.key == next_key).unwrap();
    assert_eq!(activated_start_key.stage, LifetimeStage::Finishing);
    assert_eq!(activated_next_key.stage, LifetimeStage::Active);
    let retire_at = RetireAt::get(&temp_db, EncodableG(start_key));
    assert!(retire_at.is_none());

    // Now have the Eventuality Task set the start_key's retirement block by having it handle
    // starting_finishing_block. We'll continue iterating until the retirement block just
    // to make sure state remains as expected.
    let expected_retire_at = starting_finishing_block + S::WINDOW_LENGTH;
    assert!(next_to_check < expected_retire_at);
    while next_to_check < expected_retire_at {
      daemon.add_blocks(1).await;
      run_all_tasks().await;

      let new_next_to_check =
        EventualityDb::<S>::next_to_check_for_eventualities_block(&temp_db).unwrap();
      assert!(new_next_to_check > next_to_check);
      next_to_check = new_next_to_check;
      if next_to_check == expected_retire_at {
        break;
      }

      // We expect start_key to be in the Finishing stage, and for the eventuality task to have set
      // the key to retire.
      let activated_keys = ScannerGlobalDb::<S>::active_keys(&temp_db, next_to_check).unwrap();
      assert_eq!(activated_keys.len(), 2);
      let activated_start_key = activated_keys.iter().find(|k| k.key == start_key).unwrap();
      let activated_next_key = activated_keys.iter().find(|k| k.key == next_key).unwrap();
      assert_eq!(activated_start_key.stage, LifetimeStage::Finishing);
      assert_eq!(activated_next_key.stage, LifetimeStage::Active);
      let retire_at = RetireAt::get(&temp_db, EncodableG(start_key)).unwrap();
      assert_eq!(retire_at, expected_retire_at);
    }

    // The start_key is expected to have dropped out of the active keys since its retirement block
    // has been set and next block to check is >= the retirement block. However, it's still
    // expected to be set to retire in the db.
    let final_state_check = || {
      let activated_keys = ScannerGlobalDb::<S>::active_keys(&temp_db, next_to_check).unwrap();
      assert_eq!(activated_keys.len(), 1);
      let activated_next_key = activated_keys.iter().find(|k| k.key == next_key).unwrap();
      assert_eq!(activated_next_key.stage, LifetimeStage::Active);
      let retire_at = RetireAt::get(&temp_db, EncodableG(start_key)).unwrap();
      assert_eq!(retire_at, expected_retire_at);
    };
    final_state_check();

    // Iterate once more to make sure the Eventuality Task handles the retirement block smoothly.
    assert_eq!(
      EventualityDb::<S>::next_to_check_for_eventualities_block(&temp_db).unwrap(),
      expected_retire_at
    );
    daemon.add_blocks(1).await;
    run_all_tasks().await;
    final_state_check();
    assert_eq!(
      EventualityDb::<S>::next_to_check_for_eventualities_block(&temp_db).unwrap(),
      expected_retire_at + 1
    );
  }

  /// Ensure a key's retirement block is set by the Eventuality Task once the Eventuality
  /// Task handles the key's Finishing block. This ensures the retirement block gets set
  /// to the same value for all validators. This test advances the chain first, and then
  /// iterates the tasks after (Index -> Scan -> Eventuality).
  async fn deterministic_retirement_advance_chain_first<
    S: ScannerFeed,
    D: DaemonHelper,
    Sch: Scheduler<S>,
  >(
    feed: S,
    daemon: D,
    scheduler: Sch,
    start_key: KeyFor<S>,
    next_key: KeyFor<S>,
  ) {
    daemon.reset_chain().await;
    daemon.setup_finalized_block().await;

    let (
      _temp_dir,
      temp_db,
      start_block,
      starting_finishing_block,
      mut index_task,
      mut scan_task,
      mut eventuality_task,
    ) = init_test(feed.clone(), scheduler, start_key, next_key).await;

    let mine_past_retirement_block = starting_finishing_block + (2 * S::WINDOW_LENGTH);
    let mine_n_blocks_past_retirement_block = mine_past_retirement_block - start_block;
    daemon.add_blocks(mine_n_blocks_past_retirement_block.try_into().unwrap()).await;

    let mut run_all_tasks = async || {
      index_task.run_iteration().await.unwrap();
      scan_task.run_iteration().await.unwrap();
      eventuality_task.run_iteration().await.unwrap();
    };

    // Run the tasks until the start_key's Finishing block (starting_finishing_block)
    // has been handled by the Eventuality task.
    let mut next_to_check =
      EventualityDb::<S>::next_to_check_for_eventualities_block(&temp_db).unwrap();
    while next_to_check <= starting_finishing_block {
      run_all_tasks().await;
      let new_next_to_check =
        EventualityDb::<S>::next_to_check_for_eventualities_block(&temp_db).unwrap();
      assert!(new_next_to_check > next_to_check);
      if new_next_to_check > starting_finishing_block {
        break;
      }
      next_to_check = new_next_to_check;

      // The retirement block shouldn't have been set yet by the Eventuality task since
      // it hasn't yet handled the Finishing block (starting_finishing_block).
      let retire_at = RetireAt::get(&temp_db, EncodableG(start_key));
      assert!(retire_at.is_none());
    }

    // At this point, retirement should have been set, since the Eventuality task has
    // handled starting_finishing_block.
    let retire_at = RetireAt::get(&temp_db, EncodableG(start_key)).unwrap();
    let expected_retire_at = starting_finishing_block + S::WINDOW_LENGTH;
    assert_eq!(retire_at, expected_retire_at);
  }

  /// Test the eventuality task manages various circumstances correctly.
  pub async fn eventuality_task_tests<
    S: ScannerFeed,
    D: DaemonHelper,
    Sch: Scheduler<S> + Clone,
  >(
    feed: S,
    daemon: D,
    scheduler: Sch,
    start_key: KeyFor<S>,
    next_key: KeyFor<S>,
  ) {
    println!("Executing eventuality task tests...");
    deterministic_retirement_advance_one_block_at_a_time(
      feed.clone(),
      daemon.clone(),
      scheduler.clone(),
      start_key,
      next_key,
    )
    .await;

    deterministic_retirement_advance_chain_first(
      feed.clone(),
      daemon.clone(),
      scheduler.clone(),
      start_key,
      next_key,
    )
    .await;
  }
}
