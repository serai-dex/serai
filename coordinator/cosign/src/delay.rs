use core::future::Future;
use std::time::{Duration, SystemTime};

use serai_db::{Transaction as _, Db};
use serai_task::{DoesNotError, ContinuallyRan};

use crate::evaluator::CosignedBlocks;

#[expect(clippy::cfg_not_test)]
#[cfg(not(test))]
/// How often callers should broadcast the cosigns flagged for rebroadcasting.
pub const BROADCAST_FREQUENCY: Duration = Duration::from_mins(1);
#[cfg(test)]
/// How often callers should broadcast the cosigns flagged for rebroadcasting.
pub const BROADCAST_FREQUENCY: Duration = Duration::from_secs(6);

#[expect(clippy::cfg_not_test)]
#[cfg(not(test))]
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(10);
#[cfg(test)]
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(1);

pub(crate) const ACKNOWLEDGEMENT_DELAY: Duration =
  Duration::from_secs(BROADCAST_FREQUENCY.as_secs() + SYNCHRONY_EXPECTATION.as_secs());

pub(crate) fn now_timestamp() -> Duration {
  SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .expect("current time was less than the epoch")
}

serai_db::schema!(
  SubstrateCosignDelay {
    // The latest block number marked as cosigned by the delay task.
    // Cosigned after a delay if it had events and cosigns,
    // simply marked as cosigned if the block had no events and no cosigns.
    LatestCosignedBlockNumber: () -> u64,
  }
);

/// A task to delay acknowledgement of cosigns.
pub(crate) struct CosignDelayTask<D: 'static + Send + Sync + Db> {
  pub(crate) db: D,
}

impl<D: 'static + Send + Sync + Db> ContinuallyRan for CosignDelayTask<D> {
  type Error = DoesNotError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;
      loop {
        let latest_cosigned_block_number = LatestCosignedBlockNumber::get(&self.db).unwrap_or(0);

        let mut txn = self.db.txn();
        let Some((block_number, time_evaluated, has_events)) = CosignedBlocks::try_recv(&mut txn)
        else {
          break;
        };

        // Defensive check, not likely to happen but does not allow regressing
        if block_number <= latest_cosigned_block_number {
          serai_env::warn!(
            "attempting to delay #{block_number} when #{} was already cosigned",
            latest_cosigned_block_number,
          );
          // consume and skip without sleeping.
          txn.commit();
          continue;
        }

        // No events means no cosigns to wait for, mark as cosigned immediately
        if !has_events {
          LatestCosignedBlockNumber::set(&mut txn, &block_number);
          txn.commit();
          made_progress = true;
          continue;
        }

        // Calculate when we should mark it as valid
        let now_timestamp = now_timestamp();
        let time_valid_timestamp = Duration::from_secs(time_evaluated) + ACKNOWLEDGEMENT_DELAY;

        // Drop txn during sleep
        drop(txn);

        if let Some(time_left) = time_valid_timestamp.checked_sub(now_timestamp) {
          serai_env::debug!(
            "delaying consideration of #{block_number} as cosigned for {} seconds",
            time_left.as_secs()
          );
          tokio::time::sleep(time_left).await;
        }

        let mut txn = self.db.txn();
        // Consume block to continue
        assert_eq!(
          Some((block_number, time_evaluated, has_events)),
          CosignedBlocks::try_recv(&mut txn)
        );
        LatestCosignedBlockNumber::set(&mut txn, &block_number);
        txn.commit();

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
