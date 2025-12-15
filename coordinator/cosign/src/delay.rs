use core::future::Future;
use std::time::{Duration, SystemTime};

use serai_db::*;
use serai_task::{DoesNotError, ContinuallyRan};

use crate::evaluator::CosignedBlocks;

/// How often callers should broadcast the cosigns flagged for rebroadcasting.
pub const BROADCAST_FREQUENCY: Duration = Duration::from_secs(60);
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(10);
pub(crate) const ACKNOWLEDGEMENT_DELAY: Duration =
  Duration::from_secs(BROADCAST_FREQUENCY.as_secs() + SYNCHRONY_EXPECTATION.as_secs());

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

        // Receive the next block to mark as cosigned
        let Some((block_number, time_evaluated)) = CosignedBlocks::try_recv(&mut txn) else {
          break;
        };

        // If we've already acknowledged a later block, don't regress (and don't wait).
        let already_cosigned = LatestCosignedBlockNumber::get(&txn).unwrap_or(0);
        if block_number <= already_cosigned {
          txn.commit();
          made_progress = true;
          continue;
        }

        // Calculate when we should mark it as valid
        let time_valid = Duration::from_secs(time_evaluated) + ACKNOWLEDGEMENT_DELAY;

        // Sleep until then
        tokio::time::sleep(time_valid).await;

        // Set the cosigned block
        LatestCosignedBlockNumber::set(&mut txn, &block_number);
        txn.commit();

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
