#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{
  fmt::{self, Debug},
  future::Future,
  time::Duration,
};

use tokio::sync::mpsc;

mod type_name;

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
  #[allow(dead_code)] // This is used to track if all handles have been dropped
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
    #[allow(clippy::match_same_arms)]
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
  /// The amount of seconds before this task should be polled again.
  const DELAY_BETWEEN_ITERATIONS: u64 = 5;
  /// The maximum amount of seconds before this task should be run again.
  ///
  /// Upon error, the amount of time waited will be linearly increased until this limit.
  const MAX_DELAY_BETWEEN_ITERATIONS: u64 = 120;

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
      let increase_sleep_before_next_task = |current_sleep_before_next_task: &mut u64| {
        let new_sleep = *current_sleep_before_next_task + default_sleep_before_next_task;
        // Set a limit of sleeping for two minutes
        *current_sleep_before_next_task = new_sleep.max(Self::MAX_DELAY_BETWEEN_ITERATIONS);
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
            log::warn!("{type_name}: {e:?}");
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
          () = tokio::time::sleep(Duration::from_secs(current_sleep_before_next_task)) => {},
          msg = task.run_now.recv() => {
            // Check if this is firing because the handle was dropped
            if msg.is_none() {
              break;
            }
          },
        }
      }
    }
  }
}
