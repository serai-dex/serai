//! Evaluates cosigns intended to be performed
use core::future::Future;
use std::time::{Duration, Instant};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::{
  intend, GlobalCosigningSession, GlobalCosigningSessionId, HasEvents, RequestNotableCosigns,
  delay::now_timestamp,
};

#[expect(clippy::cfg_not_test)]
#[cfg(not(test))]
pub(crate) const REQUEST_COSIGNS_SPACING: Duration = Duration::from_mins(1);
#[cfg(test)]
pub(crate) const REQUEST_COSIGNS_SPACING: Duration = Duration::from_secs(6);

pub(crate) const COSIGN_COMMIT_THRESHOLD_NUMERATOR: u128 = 83;
pub(crate) const COSIGN_COMMIT_THRESHOLD_DENOMINATOR: u128 = 100;

create_db!(
  CosignEvaluator {
    // The global cosigning session currently used as evaluator.
    CurrentGlobalCosigningSessionEvaluator:
      () -> (GlobalCosigningSessionId, GlobalCosigningSession),
  }
);

db_channel!(
  CosignEvaluatorChannels {
    // The channel to send events to the delay task. Contains the cosigned block number,
    // the time the cosign was evaluated in seconds since the epoch, and a has_cosigns
    // boolean to guard the necessity to delay on every block.
    CosignedBlocks: () -> (u64, u64, bool),
  }
);

/// Calculate the minimum threshold required for cosigning
pub(crate) fn cosign_threshold(total_stake: u64) -> u64 {
  const {
    assert!(COSIGN_COMMIT_THRESHOLD_NUMERATOR < COSIGN_COMMIT_THRESHOLD_DENOMINATOR);
  }
  u64::try_from(
    (u128::from(total_stake) * COSIGN_COMMIT_THRESHOLD_NUMERATOR) /
      COSIGN_COMMIT_THRESHOLD_DENOMINATOR,
  )
  .expect("threshold < 1") +
    1
}

pub(crate) fn current_global_cosigning_session_evaluating(
  getter: &impl Get,
) -> Option<GlobalCosigningSessionId> {
  CurrentGlobalCosigningSessionEvaluator::get(getter).map(|(id, _info)| id)
}

/// A task to determine if a block has been cosigned and we should handle it.
pub(crate) struct CosignEvaluatorTask<D: Db, R: RequestNotableCosigns> {
  pub(crate) db: D,
  pub(crate) request: R,
  pub(crate) last_request_for_cosigns: Instant,
}

impl<D: Db, R: RequestNotableCosigns> CosignEvaluatorTask<D, R> {
  /// Commit a block as evaluated and send for delay.
  fn commit_evaluated_block(mut txn: impl DbTxn, block_number: u64, has_cosigns: bool) {
    CosignedBlocks::send(&mut txn, &(block_number, now_timestamp().as_secs(), has_cosigns));
    txn.commit();
  }

  /// Fetch the currently being-evaluated global cosigning session.
  ///
  /// This is a strict function which won't panic, even with a malicious Serai node, so long as:
  /// - It's called incrementally (with an increment of 1)
  /// - It's only called for block numbers we've completed indexing on within the intend task
  /// - It's only called for block numbers after a global cosigning session has started
  /// - The global cosigning sessions channel is populated as the block declaring the session
  ///
  /// which all hold true within the context of this task and the intend task.
  ///
  /// This function will also ensure the currently evaluated global cosigning session is incremented
  /// once we finish evaluation of the prior session.
  fn currently_evaluating_global_cosigning_session_strict(
    txn: &mut impl DbTxn,
    evaluate_block_number: u64,
  ) -> (GlobalCosigningSessionId, GlobalCosigningSession) {
    let mut current_evaluator = {
      let current_evaluator = match CurrentGlobalCosigningSessionEvaluator::get(txn) {
        Some(current_evaluator) => current_evaluator,
        None => {
          let first_from_channel = intend::GlobalCosigningSessionsChannel::try_recv(txn)
            // Panic: invariant, this function should only be called if
            // the global cosigning sessions channel is populated
            .expect("fetching latest global cosigning session yet none declared");
          CurrentGlobalCosigningSessionEvaluator::set(txn, &first_from_channel);
          first_from_channel
        }
      };
      assert!(
        current_evaluator.1.start_block_number <= evaluate_block_number,
        "attempting to evaluate block {evaluate_block_number} before session start {}",
        current_evaluator.1.start_block_number
      );
      current_evaluator
    };

    if let Some(next_from_channel) = intend::GlobalCosigningSessionsChannel::peek(txn) {
      assert!(
        evaluate_block_number <= next_from_channel.1.start_block_number,
        "currently_evaluating_global_cosigning_session_strict wasn't called incrementally",
      );
      // If it's time for this session to activate, take it from the channel and set it
      // as current
      if evaluate_block_number == next_from_channel.1.start_block_number {
        intend::GlobalCosigningSessionsChannel::try_recv(txn)
          .expect("channel must have items after peek");
        CurrentGlobalCosigningSessionEvaluator::set(txn, &next_from_channel);
        current_evaluator = next_from_channel;
      }
    }

    current_evaluator
  }

  fn should_request_cosigns(last_request_for_cosigns: &mut Instant) -> bool {
    if Instant::now() < (*last_request_for_cosigns + REQUEST_COSIGNS_SPACING) {
      return false;
    }

    *last_request_for_cosigns = Instant::now();

    true
  }

  /// Evaluate non-notable cosigns, returning (weight_cosigned, lowest_common_block).
  fn evaluate_non_notable_cosigns(
    getter: &impl Get,
    evaluate_block_number: u64,
    global_cosigning_session: GlobalCosigningSessionId,
    global_cosigning_session_info: &GlobalCosigningSession,
  ) -> (u64, Option<u64>) {
    /*
      NetworksLatestCosignedBlock is populated with the latest cosigns for each network which don't
      exceed the latest global cosigning session we've evaluated the start of. This current block
      is during the latest global cosigning session we've evaluated the start of.
    */

    let mut weight_cosigned = 0;
    let mut lowest_common_block: Option<u64> = None;

    for set in &global_cosigning_session_info.cosigning_sets {
      // Check if this set cosigned this block or not
      let Some(networks_signed_cosign) = crate::NetworksLatestCosignedBlockIntaken::get(
        getter,
        global_cosigning_session,
        set.network,
      ) else {
        continue;
      };

      // A cosign commit for a block is considered to also cosign for all blocks preceding it.
      let networks_cosign_commit_reached =
        networks_signed_cosign.cosign.block_number >= evaluate_block_number;
      if networks_cosign_commit_reached {
        // serai invariant: network stakes expected valid, panic expected on overflow
        weight_cosigned += global_cosigning_session_info
          .stakes
          .get(&set.network)
          // Panic: ValidatorSet in global cosigning session without its stake
          .expect("ValidatorSet in global cosigning session yet didn't have its stake");
      }

      // Update the lowest block common to the cosigns of all these networks
      lowest_common_block = lowest_common_block
        .map(|lowest_common_block| {
          lowest_common_block.min(networks_signed_cosign.cosign.block_number)
        })
        .or(Some(networks_signed_cosign.cosign.block_number));
    }

    (weight_cosigned, lowest_common_block)
  }

  /// If the cosign threshold isn't met, request cosigns and return an error.
  /// Since the error makes the task re-run, this won't stop until the threshold weight is crossed.
  async fn ensure_cosigned(
    weight_cosigned: u64,
    total_stake: u64,
    block_number: u64,
    global_cosigning_session: GlobalCosigningSessionId,
    last_request_for_cosigns: &mut Instant,
    request: &impl RequestNotableCosigns,
    label: &str,
  ) -> Result<(), String> {
    if weight_cosigned >= cosign_threshold(total_stake) {
      return Ok(());
    }

    /*
      Request the superseding notable cosigns over the network.

      If this session hasn't yet produced notable cosigns, then we presume we'll see the desired
      non-notable cosigns as part of normal operations, without needing to explicitly request them.
    */
    if Self::should_request_cosigns(last_request_for_cosigns) {
      request
        .request_notable_cosigns(global_cosigning_session)
        .await
        // Ephemeral p2p Err: task to re-run and continue trying
        .map_err(|e| format!("Error fetching notable cosigns: {e:?}"))?;
    }

    // We return an error so the failure delay increases, before this task runs again to re-try
    Err(format!("{label} block (#{block_number}) wasn't yet cosigned. this should resolve shortly"))
  }
}

impl<D: Db, R: RequestNotableCosigns> ContinuallyRan for CosignEvaluatorTask<D, R> {
  #[cfg(test)]
  const DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_secs(1);
  #[cfg(test)]
  const MAX_DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_secs(5);

  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut prior_global_cosigning_session = None;
      let mut block_number_known_to_be_cosigned = None;
      let mut made_progress = false;
      loop {
        let mut txn = self.db.txn();
        let Some(intend::BlockEventData { block_number, has_events }) =
          intend::BlockEvents::try_recv(&mut txn)
        else {
          break;
        };

        // If no global cosigning session is evaluating yet, check if this block can be processed
        if current_global_cosigning_session_evaluating(&txn).is_none() {
          match intend::GlobalCosigningSessionsChannel::peek(&txn) {
            // No global cosigning session declared yet: this block predates all sessions, skip it
            // this means only HasEvents:No blocks have been consumed so far
            None => {
              Self::commit_evaluated_block(txn, block_number, false);
              made_progress = true;
              continue;
            }
            // A new global cosigning session was indexed and is queued but starts after this block,
            // skip it until it is reached by the evaluator loop.
            Some(next_from_channel) if next_from_channel.1.start_block_number > block_number => {
              Self::commit_evaluated_block(txn, block_number, false);
              made_progress = true;
              continue;
            }
            // Session covers this block: proceed normally
            _ => {}
          }
        }

        // Fetch the global cosigning session information
        let (global_cosigning_session, global_cosigning_session_info) =
          Self::currently_evaluating_global_cosigning_session_strict(&mut txn, block_number);

        // If the global cosigning session has changed, clear the cached `known_cosign`
        if prior_global_cosigning_session != Some(global_cosigning_session) {
          prior_global_cosigning_session = Some(global_cosigning_session);
          block_number_known_to_be_cosigned = None;
        }

        match has_events {
          // Because this had notable events, we require an explicit cosign for this block by a
          // supermajority of the prior block's validator sets
          HasEvents::Notable => {
            let mut weight_cosigned = 0;
            for set in global_cosigning_session_info.cosigning_sets {
              // Check if we have the cosign from this set
              if crate::NetworksLatestCosignedBlockIntaken::get(
                &txn,
                global_cosigning_session,
                set.network,
              )
              .map(|signed_cosign| signed_cosign.cosign.block_number) ==
                Some(block_number)
              {
                // Since we have this cosign, add the set's weight to the weight which has cosigned
                // serai invariant: network stakes expected valid, panic expected on overflow
                weight_cosigned += global_cosigning_session_info
                  .stakes
                  .get(&set.network)
                  // Panic: ValidatorSet in global cosigning session without its stake
                  .expect("ValidatorSet in global cosigning session yet didn't have its stake");
              }
            }

            Self::ensure_cosigned(
              weight_cosigned,
              global_cosigning_session_info.total_stake,
              block_number,
              global_cosigning_session,
              &mut self.last_request_for_cosigns,
              &self.request,
              "notable",
            )
            .await?;

            serai_env::debug!("got cosigns, marking notable block #{block_number} as cosigned");
          }
          // Since this block didn't have any notable events, we simply require a cosign for this
          // block or a greater block by the current validator sets
          HasEvents::NonNotable => {
            // A cosign commit for a block is considered to also cosign for all blocks preceding it.
            // (known cosign can commit to earlier blocks)
            let known_cosign_can_commit = block_number_known_to_be_cosigned >= Some(block_number);
            // If not already known to be cosigned by a cached result, evaluate the latest cosigns
            if !known_cosign_can_commit {
              let (weight_cosigned, lowest_common_cosigned_block_number) =
                Self::evaluate_non_notable_cosigns(
                  &txn,
                  block_number,
                  global_cosigning_session,
                  &global_cosigning_session_info,
                );

              Self::ensure_cosigned(
                weight_cosigned,
                global_cosigning_session_info.total_stake,
                block_number,
                global_cosigning_session,
                &mut self.last_request_for_cosigns,
                &self.request,
                "non-notable",
              )
              .await?;

              // Update the cached result for the block we know is cosigned
              /*
                There may be a higher block which was cosigned, but once we get to this block,
                we'll re-evaluate and find it then. The alternative would be an optimistic
                re-evaluation now. Both are fine, so the lower-complexity option is preferred.
              */
              block_number_known_to_be_cosigned = lowest_common_cosigned_block_number;

              serai_env::debug!(
                "got cosigns, marking non-notable block #{block_number} as cosigned"
              );
            } else {
              serai_env::debug!(
                "marking non-notable block #{block_number} as cosigned, have cached cosigns \
                 at: {:?}",
                block_number_known_to_be_cosigned
              );
            }
          }
          // If this block has no events necessitating cosigning, we can immediately consider the
          // block cosigned (making this block a NOP)
          HasEvents::No => {
            serai_env::debug!("marking no-events block #{block_number} as cosigned");
          }
        }

        // Since we checked we had the necessary cosigns, send it for delay before acknowledgement
        Self::commit_evaluated_block(txn, block_number, has_events != HasEvents::No);

        // INFOs roughly every ~1 hour, no need for repetitive logging on prod
        // helps to see "it's doing something" due to the p2p loop expectation
        #[expect(clippy::cfg_not_test)]
        #[cfg(not(test))]
        if (block_number % 500) == 0 {
          serai_env::info!("marking block #{block_number} as cosigned");
        }

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
