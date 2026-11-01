use core::{
  pin::Pin,
  task::{Poll, Context},
  time::Duration,
};
use std::time::SystemTime;

use tendermint::Network;

use crate::{ReadWriteAsBorsh, transaction::Transaction, block::Block, AggregateSignature};

pin_project_lite::pin_project! {
  /// A future for the next block's time.
  ///
  /// This future MAY be polled multiple times, repeatedly returning a time (not necessarily the
  /// same time) to use for the next block.
  ///
  /// This is primarily parameterized by the minimum time for the next block. This future will
  /// attempt to yield until the current time is greater than or equal to the minimum time for the
  /// next block, if sleeping until such a time can be represented. If such a sleep cannot be
  /// represented, this future will yield immediately, but it will always yield a time greater than
  /// or equal to the minimum time. This ensures the block will be syntactically valid, but means
  /// it MAY occur in the future (being ephemerally invalid).
  pub(super) struct MinimumBlockTime<Sleep = ()> {
    ms_since_epoch: u64,
    #[pin]
    future: Option<Sleep>,
  }
}

impl MinimumBlockTime {
  pub(super) fn new<
    T: Transaction,
    N: Network<[u8; 32], [u8; 64], AggregateSignature, ReadWriteAsBorsh<Block<T>>>,
  >(
    ms_since_epoch: u64,
  ) -> MinimumBlockTime<N::Sleep> {
    // This is `None` if the minimum time is satisfied _or_ such a sleep can't be represented
    let future = {
      let minimum_system_time =
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(ms_since_epoch));
      let time_remaining = minimum_system_time
        .and_then(|minimum_system_time| minimum_system_time.duration_since(SystemTime::now()).ok());
      time_remaining.map(N::sleep)
    };

    MinimumBlockTime { ms_since_epoch, future }
  }
}

impl<Sleep: Future<Output = ()>> Future for MinimumBlockTime<Sleep> {
  type Output = u64;
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let mut projection = self.project();

    // Determine the current time, expressed as a block's time (milliseconds since the epoch)
    let current_time = {
      let time_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
      time_since_epoch.ok().and_then(|duration| u64::try_from(duration.as_millis()).ok())
    };

    let block_time =
      match current_time.filter(|current_time| current_time >= projection.ms_since_epoch) {
        None => {
          if let Some(future) = projection.future.as_mut().as_pin_mut() {
            // Poll the future so we establish a waker for our current context
            let Poll::Ready(()) = future.poll(cx) else {
              return Poll::Pending;
            };
          }
          // Use the minimum time for the block's time
          *projection.ms_since_epoch
        }
        // Since our time is greater than or equal to the minimum time, use our time
        Some(current_time) => current_time,
      };

    /*
      Drop the future to wait until the minimum time has been reached.

      If this yielded `Poll::Ready`, this ensures we never call it again.

      If this is still pending, this cancels it, as we no longer rely on it.
    */
    projection.future.set(None);

    Poll::Ready(block_time)
  }
}

#[cfg(test)]
#[tokio::test]
async fn minimum_block_time() {
  let seconds = Duration::from_secs(10);
  let now = || SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();

  {
    let satisfied = MinimumBlockTime::<tokio::time::Sleep> { ms_since_epoch: 0, future: None };
    assert!(
      u128::from(satisfied.await).abs_diff(now()) < seconds.as_millis(),
      "`MinimumBlockTime` didn't return the current time"
    );
  }

  {
    let not_satisfied =
      MinimumBlockTime::<tokio::time::Sleep> { ms_since_epoch: u64::MAX, future: None };
    assert_eq!(not_satisfied.await, u64::MAX, "`MinimumBlockTime` didn't return the minimum time");
  }

  {
    let target = u64::try_from(now() + seconds.as_millis()).unwrap();
    let mut until_target = alloc::boxed::Box::pin(MinimumBlockTime {
      ms_since_epoch: target,
      future: Some(tokio::time::sleep(seconds)),
    });
    assert!((&mut until_target).await >= target, "yielded time was less than target");
    assert!(now() > u128::from(target), "future resolved prior to the sleep returning");
    assert!((&mut until_target).await > target, "future couldn't be polled multiple times");
  }
}
