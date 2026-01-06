use core::future::Future;
use std::time::{Duration, SystemTime};

use serai_db::*;
use serai_task::{DoesNotError, ContinuallyRan};

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
  type Error = DoesNotError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;
      loop {
        let mut txn = self.db.txn();

        // Peek the next block to mark as cosigned, without consuming yet
        let Some((block_number, time_evaluated)) = CosignedBlocks::try_recv(&mut txn) else {
          // Queue was empty -> nothing to commit, txn gets dropped
          break;
        };

        // If we've already acknowledged a later block, consume and skip (don't wait).
        let already_cosigned = LatestCosignedBlockNumber::get(&txn).unwrap_or(0);
        if block_number <= already_cosigned {
          // Clear block from queue
          txn.commit();
          continue;
        }

        // Calculate when we should mark it as valid
        let time_valid = Duration::from_secs(time_evaluated) + ACKNOWLEDGEMENT_DELAY;
        let now = now_timestamp();

        // drop txn during sleep
        drop(txn);

        if time_valid > now {
          // Sleep until then
          let time_left = time_valid - now;
          tokio::time::sleep(time_left).await;
        }

        let mut txn = self.db.txn();
        let _consumed_block = CosignedBlocks::try_recv(&mut txn);
        // Set the cosigned block
        LatestCosignedBlockNumber::set(&mut txn, &block_number);
        txn.commit();

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
