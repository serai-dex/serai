use core::future::Future;
use std::time::{Duration, SystemTime};

use serai_db::*;
use serai_task::{DoesNotError, ContinuallyRan};

use crate::{evaluator::CosignedBlocks, latest_cosigned_block_number};

#[cfg(not(any(test, feature = "dev")))]
/// How often callers should broadcast the cosigns flagged for rebroadcasting.
pub const BROADCAST_FREQUENCY: Duration = Duration::from_mins(1);
#[cfg(any(test, feature = "dev"))]
/// How often callers should broadcast the cosigns flagged for rebroadcasting.
pub const BROADCAST_FREQUENCY: Duration = Duration::from_secs(6);

#[cfg(not(any(test, feature = "dev")))]
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(10);
#[cfg(any(test, feature = "dev"))]
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(1);

pub(crate) const ACKNOWLEDGEMENT_DELAY: Duration =
  Duration::from_secs(BROADCAST_FREQUENCY.as_secs() + SYNCHRONY_EXPECTATION.as_secs());

pub(crate) fn now_timestamp() -> Duration {
  SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("error getting current timestamp")
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
          break;
        };

        let latest_cosigned_block_number = LatestCosignedBlockNumber::get(getter).unwrap_or(0);

        #[cfg(not(coverage))]
        log::debug!(
          "beginning delay: block_number={block_number}, time_evaluated={time_evaluated}, latest_cosigned_block_number={latest_cosigned_block_number}",
        );

        if block_number <= latest_cosigned_block_number {
          // If we've already acknowledged a later block, consume and skip (don't sleep).
          txn.commit();
          continue;
        }

        // Calculate when we should mark it as valid
        let now_timestamp = now_timestamp().as_secs();
        let time_valid_timestamp = time_evaluated + ACKNOWLEDGEMENT_DELAY.as_secs();

        // drop txn during sleep
        drop(txn);

        if time_valid_timestamp > now_timestamp {
          // Sleep until then
          let time_left = time_valid_timestamp - now_timestamp;
          tokio::time::sleep(Duration::from_secs(time_left)).await;
        }

        let mut txn = self.db.txn();
        // Consume block to continue
        CosignedBlocks::try_recv(&mut txn);
        // Set the cosigned block
        LatestCosignedBlockNumber::set(&mut txn, &block_number);
        txn.commit();

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
