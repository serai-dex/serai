use core::future::Future;
use std::time::{Duration, SystemTime};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::evaluator::CosignedBlocks;

/// How often callers should broadcast the cosigns flagged for rebroadcasting.
#[cfg(not(test))]
pub const BROADCAST_FREQUENCY: Duration = Duration::from_secs(60);
#[cfg(not(test))]
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(10);
/// How often callers should broadcast the cosigns flagged for rebroadcasting.
#[cfg(test)]
pub const BROADCAST_FREQUENCY: Duration = Duration::from_secs(6);
#[cfg(test)]
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(1);
pub(crate) const ACKNOWLEDGEMENT_DELAY: Duration =
  Duration::from_secs(BROADCAST_FREQUENCY.as_secs() + SYNCHRONY_EXPECTATION.as_secs());

pub(crate) fn now_timestamp() -> Duration {
  SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO)
}

create_db!(
  SubstrateCosignDelay {
    // The latest cosigned block number.
    LatestCosignedBlockNumber: () -> u64,
  }
);

/// A task to delay acknowledgement of cosigns.
pub(crate) struct CosignDelayTask<D: Db> {
  pub(crate) db: D,
}

impl<D: Db> ContinuallyRan for CosignDelayTask<D> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;

      loop {
        let mut txn = self.db.txn();

        // Peek before consuming
        let Some((block_number, time_evaluated)) = CosignedBlocks::try_recv(&mut txn) else {
          // Queue was empty -> nothing to commit
          drop(txn);
          break;
        };

        if block_number == 0u64 {
          // Clear block from queue
          txn.commit();
          continue;
        }

        // If we've already acknowledged a later block, consume and skip (don't wait).
        let already_cosigned = LatestCosignedBlockNumber::get(&txn).unwrap_or(0);
        if block_number <= already_cosigned {
          // Clear block from queue
          txn.commit();
          continue;
        }

        // Calculate when we should mark it as valid, checking for overflow to avoid panic
        let time_valid = Duration::from_secs(time_evaluated)
          .checked_add(ACKNOWLEDGEMENT_DELAY)
          .ok_or_else(|| {
            format!(
              "time_evaluated ({time_evaluated}) would overflow when adding ACKNOWLEDGEMENT_DELAY"
            )
          })?;
        let now = now_timestamp();

        if time_valid > now {
          // NOT READY YET - don't consume, just return
          // leave message in queue, check again in next task iteration
          // simulates sleeping until ready, but continually iterating until ready instead
          drop(txn);
          return Ok(made_progress);
        }

        LatestCosignedBlockNumber::set(&mut txn, &block_number);

        txn.commit();
        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
