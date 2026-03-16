use core::future::Future;
use std::time::{Duration, SystemTime};

use serai_db::*;
use serai_task::{DoesNotError, ContinuallyRan};

use crate::evaluator::{CosignedBlocks, LatestEvaluatedBlock};

#[cfg(not(any(test)))]
/// How often callers should broadcast the cosigns flagged for rebroadcasting.
pub const BROADCAST_FREQUENCY: Duration = Duration::from_mins(1);
#[cfg(any(test))]
/// How often callers should broadcast the cosigns flagged for rebroadcasting.
pub const BROADCAST_FREQUENCY: Duration = Duration::from_secs(6);

#[cfg(not(any(test)))]
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(10);
#[cfg(any(test))]
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(1);

pub(crate) const ACKNOWLEDGEMENT_DELAY: Duration =
  Duration::from_secs(BROADCAST_FREQUENCY.as_secs() + SYNCHRONY_EXPECTATION.as_secs());

pub(crate) fn now_timestamp() -> Duration {
  SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("error getting current timestamp")
}

create_db!(
  SubstrateCosignDelay {
    // The latest block number acknowledged by the delay task.
    LatestAcknowledgedBlock: () -> u64,
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

        let latest_acknowledged_block = LatestAcknowledgedBlock::get(&mut txn).unwrap_or(0);

        serai_env::debug!(
          "beginning delay: block_number={block_number}, time_evaluated={time_evaluated}, latest_acknowledged_block={latest_acknowledged_block}",
        );

        if block_number <= latest_acknowledged_block {
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
          serai_env::debug!("beginning sleep: {time_left}s");
          tokio::time::sleep(Duration::from_secs(time_left)).await;
        }

        let mut txn = self.db.txn();
        // Consume block to continue
        CosignedBlocks::try_recv(&mut txn);
        LatestAcknowledgedBlock::set(&mut txn, &block_number);
        txn.commit();

        serai_env::debug!("LatestAcknowledgedBlock={block_number}");

        made_progress = true;
      }

      // Catch up to HasEvents::No blocks that don't go through CosignedBlocks
      // they only advance LatestEvaluatedBlock. These blocks need no sleep delay.
      // since no cosign means no need for equivocation prevention
      if let Some(evaluated) = LatestEvaluatedBlock::get(&self.db) {
        let acknowledged = LatestAcknowledgedBlock::get(&self.db).unwrap_or(0);
        if evaluated > acknowledged {
          let mut txn = self.db.txn();
          LatestAcknowledgedBlock::set(&mut txn, &evaluated);
          txn.commit();
          serai_env::debug!("LatestAcknowledgedBlock={evaluated} (caught up to evaluator)");
          made_progress = true;
        }
      }

      Ok(made_progress)
    }
  }
}
