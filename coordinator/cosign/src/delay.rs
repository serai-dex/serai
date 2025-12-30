use core::future::Future;
use std::time::{Duration, SystemTime};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::evaluator::CosignedBlocks;

/// How often callers should broadcast the cosigns flagged for rebroadcasting.
pub const BROADCAST_FREQUENCY: Duration = Duration::from_secs(60);
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(10);
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
        // Every loop iteration consumes a CosignedBlocks queue message, if successful
        let cosigned_block = CosignedBlocks::try_recv(&mut txn);

        let Some((block_number, time_evaluated)) = cosigned_block else {
          // Queue was empty -> nothing to commit
          drop(txn);
          // Stop when no blocks in queue
          break;
        };

        if block_number == 0u64 {
          txn.commit();
          continue;
        }

        // If we've already acknowledged a later block, consume and skip (don't wait).
        let already_cosigned = LatestCosignedBlockNumber::get(&txn).unwrap_or(0);
        if block_number <= already_cosigned {
          txn.commit();
          continue;
        }

        // Calculate when we should mark it as valid, checking for overflow to avoid panic
        let time_evaluated_duration = Duration::from_secs(time_evaluated);
        let Some(time_valid) = time_evaluated_duration.checked_add(ACKNOWLEDGEMENT_DELAY) else {
          txn.commit();
          return Err(format!(
            "time_evaluated ({time_evaluated}) would overflow when adding ACKNOWLEDGEMENT_DELAY"
          ));
        };
        let now = now_timestamp();

        // If the time valid is greater than the current time, sleep until the time valid is reached
        if time_valid > now {
          // db txn being held and not committed until sleep completed
          // if a timeout occurs, this block will be restarted on the next iteration
          tokio::time::sleep(time_valid.saturating_sub(now)).await;
        }

        LatestCosignedBlockNumber::set(&mut txn, &block_number);

        txn.commit();
        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
