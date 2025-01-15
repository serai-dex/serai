use core::future::Future;
use std::time::{Duration, SystemTime};

use serai_db::*;
use serai_task::{DoesNotError, ContinuallyRan};

use crate::evaluator::CosignedBlocks;

/// How often callers should broadcast the cosigns flagged for rebroadcasting.
pub const BROADCAST_FREQUENCY: Duration = Duration::from_secs(60);
const SYNCHRONY_EXPECTATION: Duration = Duration::from_secs(10);
const ACKNOWLEDGEMENT_DELAY: Duration =
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

struct AwaitUndroppable<T: DbTxn>(Option<core::mem::ManuallyDrop<Undroppable<T>>>);
impl<T: DbTxn> Drop for AwaitUndroppable<T> {
  fn drop(&mut self) {
    if let Some(mut txn) = self.0.take() {
      (unsafe { core::mem::ManuallyDrop::take(&mut txn) }).close();
    }
  }
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
          txn.close();
          break;
        };

        // Calculate when we should mark it as valid
        let time_valid =
          SystemTime::UNIX_EPOCH + Duration::from_secs(time_evaluated) + ACKNOWLEDGEMENT_DELAY;
        // Sleep until then
        let mut txn = AwaitUndroppable(Some(core::mem::ManuallyDrop::new(txn)));
        tokio::time::sleep(SystemTime::now().duration_since(time_valid).unwrap_or(Duration::ZERO))
          .await;
        let mut txn = core::mem::ManuallyDrop::into_inner(txn.0.take().unwrap());

        // Set the cosigned block
        LatestCosignedBlockNumber::set(&mut txn, &block_number);
        txn.commit();

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
