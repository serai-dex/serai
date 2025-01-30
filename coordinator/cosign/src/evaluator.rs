use core::future::Future;
use std::time::{Duration, Instant, SystemTime};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::{
  HasEvents, GlobalSession, NetworksLatestCosignedBlock, RequestNotableCosigns,
  intend::{GlobalSessionsChannel, BlockEventData, BlockEvents},
};

create_db!(
  SubstrateCosignEvaluator {
    // The global session currently being evaluated.
    CurrentlyEvaluatedGlobalSession: () -> ([u8; 32], GlobalSession),
  }
);

db_channel!(
  SubstrateCosignEvaluatorChannels {
    // (cosigned block, time cosign was evaluated)
    CosignedBlocks: () -> (u64, u64),
  }
);

// This is a strict function which won't panic, even with a malicious Serai node, so long as:
// - It's called incrementally (with an increment of 1)
// - It's only called for block numbers we've completed indexing on within the intend task
// - It's only called for block numbers after a global session has started
// - The global sessions channel is populated as the block declaring the session is indexed
// Which all hold true within the context of this task and the intend task.
//
// This function will also ensure the currently evaluated global session is incremented once we
// finish evaluation of the prior session.
fn currently_evaluated_global_session_strict(
  txn: &mut impl DbTxn,
  block_number: u64,
) -> ([u8; 32], GlobalSession) {
  let mut res = {
    let existing = match CurrentlyEvaluatedGlobalSession::get(txn) {
      Some(existing) => existing,
      None => {
        let first = GlobalSessionsChannel::try_recv(txn)
          .expect("fetching latest global session yet none declared");
        CurrentlyEvaluatedGlobalSession::set(txn, &first);
        first
      }
    };
    assert!(
      existing.1.start_block_number <= block_number,
      "candidate's start block number exceeds our block number"
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

/// A task to determine if a block has been cosigned and we should handle it.
pub(crate) struct CosignEvaluatorTask<D: Db, R: RequestNotableCosigns> {
  pub(crate) db: D,
  pub(crate) request: R,
  pub(crate) last_request_for_cosigns: Instant,
}

impl<D: Db, R: RequestNotableCosigns> ContinuallyRan for CosignEvaluatorTask<D, R> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    let should_request_cosigns = |last_request_for_cosigns: &mut Instant| {
      const REQUEST_COSIGNS_SPACING: Duration = Duration::from_secs(60);
      if Instant::now() < (*last_request_for_cosigns + REQUEST_COSIGNS_SPACING) {
        return false;
      }
      *last_request_for_cosigns = Instant::now();
      true
    };

    async move {
      let mut known_cosign = None;
      let mut made_progress = false;
      loop {
        let mut txn = self.db.txn();
        let Some(BlockEventData { block_number, has_events }) = BlockEvents::try_recv(&mut txn)
        else {
          break;
        };

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
                    "ValidatorSet in global session yet didn't have its stake".to_string()
                  })?;
              }
            }
            // Check if the sum weight doesn't cross the required threshold
            if weight_cosigned < (((global_session_info.total_stake * 83) / 100) + 1) {
              // Request the necessary cosigns over the network
              if should_request_cosigns(&mut self.last_request_for_cosigns) {
                self
                  .request
                  .request_notable_cosigns(global_session)
                  .await
                  .map_err(|e| format!("{e:?}"))?;
              }
              // We return an error so the delay before this task is run again increases
              return Err(format!(
                "notable block (#{block_number}) wasn't yet cosigned. this should resolve shortly",
              ));
            }

            log::info!("marking notable block #{block_number} as cosigned");
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
              /*
                LatestCosign is populated with the latest cosigns for each network which don't
                exceed the latest global session we've evaluated the start of. This current block
                is during the latest global session we've evaluated the start of.
              */

              let mut weight_cosigned = 0;
              let mut lowest_common_block: Option<u64> = None;
              for set in global_session_info.sets {
                // Check if this set cosigned this block or not
                let Some(cosign) =
                  NetworksLatestCosignedBlock::get(&txn, global_session, set.network)
                else {
                  continue;
                };
                if cosign.cosign.block_number >= block_number {
                  weight_cosigned +=
                    global_session_info.stakes.get(&set.network).ok_or_else(|| {
                      "ValidatorSet in global session yet didn't have its stake".to_string()
                    })?;
                }

                // Update the lowest block common to all of these cosigns
                lowest_common_block = lowest_common_block
                  .map(|existing| existing.min(cosign.cosign.block_number))
                  .or(Some(cosign.cosign.block_number));
              }

              // Check if the sum weight doesn't cross the required threshold
              if weight_cosigned < (((global_session_info.total_stake * 83) / 100) + 1) {
                // Request the superseding notable cosigns over the network
                // If this session hasn't yet produced notable cosigns, then we presume we'll see
                // the desired non-notable cosigns as part of normal operations, without needing to
                // explicitly request them
                if should_request_cosigns(&mut self.last_request_for_cosigns) {
                  self
                    .request
                    .request_notable_cosigns(global_session)
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                }
                // We return an error so the delay before this task is run again increases
                return Err(format!(
                  "block (#{block_number}) wasn't yet cosigned. this should resolve shortly",
                ));
              }

              // Update the cached result for the block we know is cosigned
              /*
                There may be a higher block which was cosigned, but once we get to this block,
                we'll re-evaluate and find it then. The alternative would be an optimistic
                re-evaluation now. Both are fine, so the lower-complexity option is preferred.
              */
              known_cosign = lowest_common_block;
            }

            log::debug!("marking non-notable block #{block_number} as cosigned");
          }
          // If this block has no events necessitating cosigning, we can immediately consider the
          // block cosigned (making this block a NOP)
          HasEvents::No => {}
        }

        // Since we checked we had the necessary cosigns, send it for delay before acknowledgement
        CosignedBlocks::send(
          &mut txn,
          &(
            block_number,
            SystemTime::now()
              .duration_since(SystemTime::UNIX_EPOCH)
              .unwrap_or(Duration::ZERO)
              .as_secs(),
          ),
        );
        txn.commit();

        if (block_number % 500) == 0 {
          log::info!("marking block #{block_number} as cosigned");
        }

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
