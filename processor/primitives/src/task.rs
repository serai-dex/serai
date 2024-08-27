use core::time::Duration;

use tokio::sync::mpsc;

/// A handle to immediately run an iteration of a task.
#[derive(Clone)]
pub struct RunNowHandle(mpsc::Sender<()>);
/// An instruction recipient to immediately run an iteration of a task.
pub struct RunNowRecipient(mpsc::Receiver<()>);

impl RunNowHandle {
  /// Create a new run-now handle to be assigned to a task.
  pub fn new() -> (Self, RunNowRecipient) {
    // Uses a capacity of 1 as any call to run as soon as possible satisfies all calls to run as
    // soon as possible
    let (send, recv) = mpsc::channel(1);
    (Self(send), RunNowRecipient(recv))
  }

  /// Tell the task to run now (and not whenever its next iteration on a timer is).
  ///
  /// Panics if the task has been dropped.
  pub fn run_now(&self) {
    #[allow(clippy::match_same_arms)]
    match self.0.try_send(()) {
      Ok(()) => {}
      // NOP on full, as this task will already be ran as soon as possible
      Err(mpsc::error::TrySendError::Full(())) => {}
      Err(mpsc::error::TrySendError::Closed(())) => {
        panic!("task was unexpectedly closed when calling run_now")
      }
    }
  }
}

/// A task to be continually ran.
#[async_trait::async_trait]
pub trait ContinuallyRan: Sized {
  /// The amount of seconds before this task should be polled again.
  const DELAY_BETWEEN_ITERATIONS: u64 = 5;
  /// The maximum amount of seconds before this task should be run again.
  ///
  /// Upon error, the amount of time waited will be linearly increased until this limit.
  const MAX_DELAY_BETWEEN_ITERATIONS: u64 = 120;

  /// Run an iteration of the task.
  ///
  /// If this returns `true`, all dependents of the task will immediately have a new iteration ran
  /// (without waiting for whatever timer they were already on).
  async fn run_iteration(&mut self) -> Result<bool, String>;

  /// Continually run the task.
  ///
  /// This returns a channel which can have a message set to immediately trigger a new run of an
  /// iteration.
  async fn continually_run(mut self, mut run_now: RunNowRecipient, dependents: Vec<RunNowHandle>) {
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
          log::warn!("{}", e);
          increase_sleep_before_next_task(&mut current_sleep_before_next_task);
        }
      }

      // Don't run the task again for another few seconds UNLESS told to run now
      tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(current_sleep_before_next_task)) => {},
        msg = run_now.0.recv() => assert_eq!(msg, Some(()), "run now handle was dropped"),
      }
    }
  }
}
