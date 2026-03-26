use core::future::Future;
use std::time::{Duration, Instant};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::{
  GlobalSession, HasEvents, NetworksLatestCosignedBlock, RequestNotableCosigns,
  delay::now_timestamp,
  intend::{BlockEventData, BlockEvents, GlobalSessionsChannel},
};

#[cfg(not(any(test)))]
pub(crate) const REQUEST_COSIGNS_SPACING: Duration = Duration::from_mins(1);
#[cfg(any(test))]
pub(crate) const REQUEST_COSIGNS_SPACING: Duration = Duration::from_secs(6);

const COSIGN_COMMIT_THRESHOLD_NUMERATOR: u128 = 83;
const COSIGN_COMMIT_THRESHOLD_DENOMINATOR: u128 = 100;

create_db!(
  SubstrateCosignEvaluator {
    // The global session currently being evaluated.
    CurrentlyEvaluatedGlobalSession: () -> ([u8; 32], GlobalSession),
  }
);

db_channel!(
  SubstrateCosignEvaluatorChannels {
    // (cosigned block, time cosign was evaluated, has_events)
    CosignedBlocks: () -> (u64, u64, bool),
  }
);

/// Commit a block as evaluated without sending it for cosign delay.
fn commit_evaluated_block(mut txn: impl DbTxn, block_number: u64, has_events: bool) {
  CosignedBlocks::send(&mut txn, &(block_number, now_timestamp().as_secs(), has_events));
  txn.commit();
}

/// This is a strict function which won't panic, even with a malicious Serai node, so long as:
/// - It's called incrementally (with an increment of 1)
/// - It's only called for block numbers we've completed indexing on within the intend task
/// - It's only called for block numbers after a global session has started
/// - The global sessions channel is populated as the block declaring the session is indexed
/// Which all hold true within the context of this task and the intend task.
///
/// This function will also ensure the currently evaluated global session is incremented once we
/// finish evaluation of the prior session.
fn currently_evaluated_global_session_strict(
  txn: &mut impl DbTxn,
  block_number: u64,
) -> ([u8; 32], GlobalSession) {
  let mut res = {
    let existing = match CurrentlyEvaluatedGlobalSession::get(txn) {
      Some(existing) => existing,
      None => {
        let first = GlobalSessionsChannel::try_recv(txn)
          // Panic: invariant, this function should only be called if
          // the global sessions channel is populated
          .expect("fetching latest global session yet none declared");
        CurrentlyEvaluatedGlobalSession::set(txn, &first);
        first
      }
    };
    assert!(
      existing.1.start_block_number <= block_number,
      "candidate's start block number ({:#?}) exceeds our block number ({block_number})",
      existing.1.start_block_number
    );
    existing
  };

  if let Some(next) = GlobalSessionsChannel::peek(txn) {
    assert!(
      block_number <= next.1.start_block_number,
      "currently_evaluated_global_session_strict wasn't called incrementally"
    );
    // If it's time for this session to activate, take it from the channel and set it
    if block_number == next.1.start_block_number {
      GlobalSessionsChannel::try_recv(txn).unwrap();
      CurrentlyEvaluatedGlobalSession::set(txn, &next);
      res = next;
    }
  }

  res
}

pub(crate) fn currently_evaluated_global_session(getter: &impl Get) -> Option<[u8; 32]> {
  CurrentlyEvaluatedGlobalSession::get(getter).map(|(id, _info)| id)
}

fn should_request_cosigns(last_request_for_cosigns: &mut Instant) -> bool {
  if Instant::now() < (*last_request_for_cosigns + REQUEST_COSIGNS_SPACING) {
    return false;
  }

  *last_request_for_cosigns = Instant::now();

  true
}

//// Calculate the minimum threshold required for cosigning
pub(crate) fn cosign_threshold(total_stake: u64) -> u64 {
  u64::try_from(
    (u128::from(total_stake) * COSIGN_COMMIT_THRESHOLD_NUMERATOR) /
      COSIGN_COMMIT_THRESHOLD_DENOMINATOR,
  )
  .expect("threshold < 1") +
    1
}

/// Evaluate non-notable cosigns, returning (weight_cosigned, lowest_common_block).
fn evaluate_non_notable_cosigns(
  getter: &impl Get,
  block_number: u64,
  global_session: [u8; 32],
  global_session_info: &GlobalSession,
) -> Result<(u64, Option<u64>), String> {
  /*
    LatestCosign is populated with the latest cosigns for each network which don't
    exceed the latest global session we've evaluated the start of. This current block
    is during the latest global session we've evaluated the start of.
  */

  let mut weight_cosigned = 0;
  let mut lowest_common_block: Option<u64> = None;

  for set in &global_session_info.sets {
    // Check if this set cosigned this block or not
    let Some(signed_cosign) = NetworksLatestCosignedBlock::get(getter, global_session, set.network)
    else {
      continue;
    };

    if signed_cosign.cosign.block_number >= block_number {
      weight_cosigned += global_session_info
        .stakes
        .get(&set.network)
        .ok_or_else(|| "ValidatorSet in global session yet didn't have its stake".to_owned())?;
    }

    // Update the lowest block common to all of these cosigns
    lowest_common_block = lowest_common_block
      .map(|existing| existing.min(signed_cosign.cosign.block_number))
      .or(Some(signed_cosign.cosign.block_number));
  }

  Ok((weight_cosigned, lowest_common_block))
}

/// If the cosign threshold isn't met, request cosigns and return an error.
async fn ensure_cosigned(
  weight_cosigned: u64,
  total_stake: u64,
  block_number: u64,
  global_session: [u8; 32],
  last_request_for_cosigns: &mut Instant,
  request: &impl RequestNotableCosigns,
  label: &str,
) -> Result<(), String> {
  if weight_cosigned >= cosign_threshold(total_stake) {
    return Ok(());
  }

  // For HasEvents::Notable request the superseding notable cosigns over the network
  // If this session hasn't yet produced notable cosigns, then we presume we'll see
  // the desired non-notable cosigns as part of normal operations, without needing to
  // explicitly request them
  //
  // For HasEvents::NonNotable request the necessary cosigns over the network
  if should_request_cosigns(last_request_for_cosigns) {
    request
      .request_notable_cosigns(global_session)
      .await
      .map_err(|e| format!("Error fetching notable cosigns: {e:?}"))?;
  }

  // We return an error so the delay before this task is run again increases
  Err(format!("{label} block (#{block_number}) wasn't yet cosigned. this should resolve shortly"))
}

/// A task to determine if a block has been cosigned and we should handle it.
pub(crate) struct CosignEvaluatorTask<D: Db, R: RequestNotableCosigns> {
  pub(crate) db: D,
  pub(crate) request: R,
  pub(crate) last_request_for_cosigns: Instant,
}

impl<D: Db, R: RequestNotableCosigns> ContinuallyRan for CosignEvaluatorTask<D, R> {
  #[cfg(test)]
  const DELAY_BETWEEN_ITERATIONS: u64 = 1;
  #[cfg(test)]
  const MAX_DELAY_BETWEEN_ITERATIONS: u64 = 5;

  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut known_cosign = None;
      let mut made_progress = false;
      loop {
        let mut txn = self.db.txn();
        let Some(BlockEventData { block_number, has_events }) = BlockEvents::try_recv(&mut txn)
        else {
          break;
        };

        // If no session is being evaluated yet, check if this block can be processed
        if currently_evaluated_global_session(&txn).is_none() {
          match GlobalSessionsChannel::peek(&txn) {
            // No global session declared yet: this block predates all sessions, skip it
            // this means only HasEvents:No blocks have been consumed so far
            None => {
              commit_evaluated_block(txn, block_number, false);
              made_progress = true;
              continue;
            }
            // Session queued but starts after this block, skip it
            Some(next) if next.1.start_block_number > block_number => {
              commit_evaluated_block(txn, block_number, false);
              made_progress = true;
              continue;
            }
            // Session covers this block: proceed normally
            _ => {}
          }
        }

        // Fetch the global session information
        let (global_session, global_session_info) =
          currently_evaluated_global_session_strict(&mut txn, block_number);

        match has_events {
          // Because this had notable events, we require an explicit cosign for this block by a
          // supermajority of the prior block's validator sets
          HasEvents::Notable => {
            let mut weight_cosigned = 0;
            for set in global_session_info.sets {
              // Check if we have the cosign from this set
              if NetworksLatestCosignedBlock::get(&txn, global_session, set.network)
                .map(|signed_cosign| signed_cosign.cosign.block_number) ==
                Some(block_number)
              {
                // Since have this cosign, add the set's weight to the weight which has cosigned
                weight_cosigned +=
                  global_session_info.stakes.get(&set.network).ok_or_else(|| {
                    "ValidatorSet in global session yet didn't have its stake".to_owned()
                  })?;
              }
            }

            ensure_cosigned(
              weight_cosigned,
              global_session_info.total_stake,
              block_number,
              global_session,
              &mut self.last_request_for_cosigns,
              &self.request,
              "notable",
            )
            .await?;

            serai_env::debug!("marking notable block #{block_number} as cosigned");
          }
          // Since this block didn't have any notable events, we simply require a cosign for this
          // block or a greater block by the current validator sets
          HasEvents::NonNotable => {
            // Check if this was satisfied by a cached result which wasn't calculated incrementally
            let known_cosigned = if let Some(known_cosign) = known_cosign {
              known_cosign >= block_number
            } else {
              // Clear `known_cosign` which is no longer helpful
              known_cosign = None;
              false
            };

            // If it isn't already known to be cosigned, evaluate the latest cosigns
            if !known_cosigned {
              let (weight_cosigned, lowest_common_block) = evaluate_non_notable_cosigns(
                &txn,
                block_number,
                global_session,
                &global_session_info,
              )?;

              ensure_cosigned(
                weight_cosigned,
                global_session_info.total_stake,
                block_number,
                global_session,
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
              known_cosign = lowest_common_block;
            }

            serai_env::debug!("marking non-notable block #{block_number} as cosigned");
          }
          // If this block has no events necessitating cosigning, we can immediately consider the
          // block cosigned (making this block a NOP)
          HasEvents::No => {
            commit_evaluated_block(txn, block_number, false);
            made_progress = true;
            continue;
          }
        }

        // Since we checked we had the necessary cosigns, send it for delay before acknowledgement
        commit_evaluated_block(txn, block_number, true);

        // INFOs roughly every ~1 hour, no need for repetitive logging on prod,
        #[cfg(not(test))]
        if (block_number % 500) == 0 {
          serai_env::prod_info!("marking block #{block_number} as cosigned");
        }
        // for tests debug on every block
        #[cfg(test)]
        serai_env::debug!("marking block #{block_number} as cosigned");

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
