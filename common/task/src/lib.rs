#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{
  fmt::{self, Debug},
  future::Future,
  time::Duration,
};

use futures::stream::{StreamExt as _, FuturesOrdered};

use tokio::sync::mpsc;

mod type_name;

/// Test helpers for asserting [`ContinuallyRan`] task iteration behavior.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

/// A handle for a task.
///
/// The task will only stop running once all handles for it are dropped.
//
// `run_now` isn't infallible if the task may have been closed. `run_now` on a closed task would
// either need to panic (historic behavior), silently drop the fact the task can't be run, or
// return an error. Instead of having a potential panic, and instead of modeling the error
// behavior, this task can't be closed unless all handles are dropped, ensuring calls to `run_now`
// are infallible.
#[derive(Clone)]
pub struct TaskHandle {
  run_now: mpsc::Sender<()>,
  #[expect(dead_code)] // This is used to track if all handles have been dropped
  close: mpsc::Sender<()>,
}

/// A task's internal structures.
pub struct Task {
  run_now: mpsc::Receiver<()>,
  close: mpsc::Receiver<()>,
}

impl Task {
  /// Create a new task definition.
  pub fn new() -> (Self, TaskHandle) {
    // Uses a capacity of 1 as any call to run as soon as possible satisfies all calls to run as
    // soon as possible
    let (run_now_send, run_now_recv) = mpsc::channel(1);
    // And any call to close satisfies all calls to close
    let (close_send, close_recv) = mpsc::channel(1);
    (
      Self { run_now: run_now_recv, close: close_recv },
      TaskHandle { run_now: run_now_send, close: close_send },
    )
  }
}

impl TaskHandle {
  /// Tell the task to run now (and not whenever its next iteration on a timer is).
  pub fn run_now(&self) {
    #[expect(clippy::match_same_arms)]
    match self.run_now.try_send(()) {
      Ok(()) => {}
      // NOP on full, as this task will already be ran as soon as possible
      Err(mpsc::error::TrySendError::Full(())) => {}
      Err(mpsc::error::TrySendError::Closed(())) => {
        // The task should only be closed if all handles are dropped, and this one hasn't been
        panic!("task was unexpectedly closed when calling run_now")
      }
    }
  }
}

/// An enum which can't be constructed, representing that the task does not error.
pub enum DoesNotError {}
impl Debug for DoesNotError {
  fn fmt(&self, _: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
    // This type can't be constructed so we'll never have a `&self` to call this fn with
    unreachable!()
  }
}

/// A task to be continually ran.
pub trait ContinuallyRan: Sized + Send {
  /// The amount of time before this task should be polled again.
  const DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_secs(5);
  /// The maximum amount of time before this task should be run again.
  ///
  /// Upon error, the amount of time waited will be linearly increased until this limit.
  const MAX_DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_mins(2);

  /// The error potentially yielded upon running an iteration of this task.
  type Error: Debug;

  /// Run an iteration of the task.
  ///
  /// If this returns `true`, all dependents of the task will immediately have a new iteration ran
  /// (without waiting for whatever timer they were already on).
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>>;

  /// Continually run the task.
  fn continually_run(
    mut self,
    mut task: Task,
    dependents: Vec<TaskHandle>,
  ) -> impl Send + Future<Output = ()> {
    async move {
      // The default number of seconds to sleep before running the task again
      let default_sleep_before_next_task = Self::DELAY_BETWEEN_ITERATIONS;
      // The current number of seconds to sleep before running the task again
      // We increment this upon errors in order to not flood the logs with errors
      let mut current_sleep_before_next_task = default_sleep_before_next_task;
      let increase_sleep_before_next_task = |current_sleep_before_next_task: &mut Duration| {
        let new_sleep = *current_sleep_before_next_task + default_sleep_before_next_task;
        // Set a limit of sleeping **at most** two minutes
        // use min to get the smallest value: either new_sleep, or 2 minutes. Never greater
        *current_sleep_before_next_task = new_sleep.min(Self::MAX_DELAY_BETWEEN_ITERATIONS);
      };

      loop {
        // If we were told to close/all handles were dropped, drop it
        {
          let should_close = task.close.try_recv();
          match should_close {
            Ok(()) | Err(mpsc::error::TryRecvError::Disconnected) => break,
            Err(mpsc::error::TryRecvError::Empty) => {}
          }
        }

        match self.run_iteration().await {
          Ok(run_dependents) => {
            // Upon a successful (error-free) loop iteration, reset the amount of time we sleep
            current_sleep_before_next_task = default_sleep_before_next_task;

            if run_dependents {
              for dependent in &dependents {
                dependent.run_now();
              }
            }
          }
          Err(e) => {
            // Get the type name
            let type_name = type_name::strip_type_name(core::any::type_name::<Self>());
            // Print the error as a warning, prefixed by the task's type
            serai_env::warn!("{type_name}: {e:?}");
            increase_sleep_before_next_task(&mut current_sleep_before_next_task);
          }
        }

        // Don't run the task again for another few seconds UNLESS told to run now
        /*
          We could replace tokio::mpsc with async_channel, tokio::time::sleep with
          patchable_async_sleep::sleep, and tokio::select with futures_lite::future::or
          It isn't worth the effort when patchable_async_sleep::sleep will still resolve to tokio
        */
        tokio::select! {
          () = tokio::time::sleep(current_sleep_before_next_task) => {},
          msg = task.run_now.recv() => {
            // Check if this is firing because the handle was dropped
            if msg.is_none() {
              break
            }
          },
        }
      }
    }
  }
}

/// A trait for processing a range of futures with a prefetch pipeline.
///
/// Implementors define how to fetch a single item ([`fetch_item`]) and how to process it
/// ([`process_item`]). The provided [`process_range`] method handles the pipeline: it prefetches
/// [`ITEMS_TO_PROCESS_AT_ONCE`] items ahead using `FuturesOrdered` to minimize RPC latency,
/// then processes each item in order to increase throughput.
pub trait FuturesRangeProcessor: ContinuallyRan {
  /// The decoded data for a single item, produced by [`fetch_item`] and consumed by
  /// [`process_item`].
  type Item: Send;

  /// How many items to prefetch ahead via concurrent RPC calls.
  const ITEMS_TO_PROCESS_AT_ONCE: u64;

  /// Fetch a single item by number.
  fn fetch_item(
    &self,
    number: u64,
  ) -> impl Send + 'static + Future<Output = Result<(u64, Self::Item), Self::Error>>;

  /// Process a single item that has already been fetched.
  fn process_item(&mut self, number: u64, item: Self::Item) -> Result<(), Self::Error>;

  /// Process a range of items from `start` to `end` (inclusive) using a prefetch pipeline.
  ///
  /// Returns `Ok(true)` if at least one item was processed, `Ok(false)` if `start > end`.
  fn process_range(
    &mut self,
    start: u64,
    end: u64,
  ) -> impl Send + Future<Output = Result<bool, Self::Error>>
  where
    Self::Error: Send,
  {
    async move {
      async fn with_test_delay<F: core::future::Future>(future: F) -> F::Output {
        #[cfg(any(test, feature = "test-helpers"))]
        if std::env::var("NO_TASK_RANGE_DELAY").is_err() {
          tokio::time::sleep(core::time::Duration::from_nanos(10)).await;
        }
        future.await
      }

      let mut made_progress = false;
      if start > end {
        return Ok(made_progress);
      }

      // FuturesOrdered can be bad practice due to potentially causing tiemouts if it isn't
      // sufficiently polled. Considering our processing loop is minimal and it does poll this,
      // it's fine.
      let mut set = FuturesOrdered::new();

      for i in start ..= end.min(start + Self::ITEMS_TO_PROCESS_AT_ONCE) {
        set.push_back(with_test_delay(self.fetch_item(i)));
      }

      for number in start ..= end {
        // Get the next item in our queue
        let (popped_number, item) = set.next().await.unwrap()?;
        assert_eq!(number, popped_number);

        // Re-populate the queue
        let next_queue_item = number + Self::ITEMS_TO_PROCESS_AT_ONCE + 1;
        if next_queue_item <= end {
          set.push_back(with_test_delay(self.fetch_item(next_queue_item)));
        }

        self.process_item(number, item)?;
        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
