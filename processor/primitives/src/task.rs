use core::{future::Future, time::Duration};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, Mutex};

enum Closed {
  NotClosed(Option<oneshot::Receiver<()>>),
  Closed,
}

/// A handle for a task.
#[derive(Clone)]
pub struct TaskHandle {
  run_now: mpsc::Sender<()>,
  close: mpsc::Sender<()>,
  closed: Arc<Mutex<Closed>>,
}
/// A task's internal structures.
pub struct Task {
  run_now: mpsc::Receiver<()>,
  close: mpsc::Receiver<()>,
  closed: oneshot::Sender<()>,
}

impl Task {
  /// Create a new task definition.
  pub fn new() -> (Self, TaskHandle) {
    // Uses a capacity of 1 as any call to run as soon as possible satisfies all calls to run as
    // soon as possible
    let (run_now_send, run_now_recv) = mpsc::channel(1);
    // And any call to close satisfies all calls to close
    let (close_send, close_recv) = mpsc::channel(1);
    let (closed_send, closed_recv) = oneshot::channel();
    (
      Self { run_now: run_now_recv, close: close_recv, closed: closed_send },
      TaskHandle {
        run_now: run_now_send,
        close: close_send,
        closed: Arc::new(Mutex::new(Closed::NotClosed(Some(closed_recv)))),
      },
    )
  }
}

impl TaskHandle {
  /// Tell the task to run now (and not whenever its next iteration on a timer is).
  ///
  /// Panics if the task has been dropped.
  pub fn run_now(&self) {
    #[allow(clippy::match_same_arms)]
    match self.run_now.try_send(()) {
      Ok(()) => {}
      // NOP on full, as this task will already be ran as soon as possible
      Err(mpsc::error::TrySendError::Full(())) => {}
      Err(mpsc::error::TrySendError::Closed(())) => {
        panic!("task was unexpectedly closed when calling run_now")
      }
    }
  }

  /// Close the task.
  ///
  /// Returns once the task shuts down after it finishes its current iteration (which may be of
  /// unbounded time).
  pub async fn close(self) {
    // If another instance of the handle called tfhis, don't error
    let _ = self.close.send(()).await;
    // Wait until we receive the closed message
    let mut closed = self.closed.lock().await;
    match &mut *closed {
      Closed::NotClosed(ref mut recv) => {
        assert_eq!(recv.take().unwrap().await, Ok(()), "continually ran task dropped itself?");
        *closed = Closed::Closed;
      }
      Closed::Closed => {}
    }
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

  /// Run an iteration of the task.
  ///
  /// If this returns `true`, all dependents of the task will immediately have a new iteration ran
  /// (without waiting for whatever timer they were already on).
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>>;

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
            log::warn!("{}", e);
            increase_sleep_before_next_task(&mut current_sleep_before_next_task);
          }
        }

        // Don't run the task again for another few seconds UNLESS told to run now
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

      task.closed.send(()).unwrap();
    }
  }
}
