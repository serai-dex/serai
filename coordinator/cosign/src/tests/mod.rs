#[cfg(test)]
mod intend;

#[cfg(test)]
mod evaluator;

#[cfg(test)]
mod delay;

#[cfg(test)]
mod cosigning;

use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
};

use serai_task::{ContinuallyRan, Task, TaskHandle};

use crate::RequestNotableCosigns;

/// Waits until a condition is met, with a timeout.
///
/// Polls the condition at `interval` and panics if `timeout` is exceeded.
///
/// # Examples
/// ```ignore
/// // Simple condition (no value printed on timeout)
/// wait_until!(some_condition());
///
/// // With comparison - prints actual value on timeout
/// wait_until!(LatestCosignedBlockNumber::get(&db) => Some(3));
///
/// // With custom timeout
/// wait_until!(value_expr => expected, Duration::from_secs(30));
/// ```
#[allow(unused_macro_rules)]
macro_rules! wait_until {
  // Simple condition without value printing
  ($condition:expr) => {
    wait_until!(@simple $condition, Duration::from_secs(60), Duration::from_millis(10))
  };
  ($condition:expr, $timeout:expr) => {
    wait_until!(@simple $condition, $timeout, Duration::from_millis(10))
  };
  ($condition:expr, $timeout:expr, $interval:expr) => {
    wait_until!(@simple $condition, $timeout, $interval)
  };
  // Comparison form: wait_until!(actual_expr => expected_value)
  // Prints actual value on timeout
  ($actual:expr => $expected:expr) => {
    wait_until!(@compare $actual, $expected, Duration::from_secs(60), Duration::from_millis(10))
  };
  ($actual:expr => $expected:expr, $timeout:expr) => {
    wait_until!(@compare $actual, $expected, $timeout, Duration::from_millis(10))
  };
  ($actual:expr => $expected:expr, $timeout:expr, $interval:expr) => {
    wait_until!(@compare $actual, $expected, $timeout, $interval)
  };
  // Internal: simple condition
  (@simple $condition:expr, $timeout:expr, $interval:expr) => {
    tokio::select! {
      _ = async {
        loop {
          if $condition {
            break;
          }
          tokio::time::sleep($interval).await;
        }
      } => {}
      _ = tokio::time::sleep($timeout) => {
        panic!("timeout waiting for condition: {}", stringify!($condition));
      }
    }
  };
  // Internal: comparison with value printing
  (@compare $actual:expr, $expected:expr, $timeout:expr, $interval:expr) => {{
    let expected = $expected;
    let mut last_actual = None;
    tokio::select! {
      _ = async {
        loop {
          let actual = $actual;
          if actual == expected {
            break;
          }
          last_actual = Some(actual);
          tokio::time::sleep($interval).await;
        }
      } => {}
      _ = tokio::time::sleep($timeout) => {
        panic!(
          "timeout waiting for {} to equal {:?}, last value was {:?}",
          stringify!($actual),
          expected,
          last_actual
        );
      }
    }
  }};
}
pub(crate) use wait_until;

pub(crate) struct Test;
impl Test {
  pub(crate) async fn assert_task_run_iteration_and_check_progress(
    task: &mut impl ContinuallyRan,
    made_progress: bool,
  ) {
    assert_eq!(task.run_iteration().await.unwrap(), made_progress);
  }

  pub(crate) async fn assert_task_run_and_failed_with(task: &mut impl ContinuallyRan, error: &str) {
    let err = task.run_iteration().await.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(err_str.contains(error), "{err_str}");
  }

  /// Spawns a task to run continuously in the background, returning its handle.
  ///
  /// This allows testing a task while it runs as expected (with the full `continually_run`
  /// loop including delays and error handling). Drop the returned `TaskHandle` to stop the task.
  pub fn spawn_task_continually_running<T: ContinuallyRan + 'static>(
    task_runner: T,
    dependents: Vec<TaskHandle>,
  ) -> TaskHandle {
    let (task, task_handle) = Task::new();
    tokio::spawn(task_runner.continually_run(task, dependents));
    task_handle
  }
}

pub(crate) trait IntoTask {
  type Task: ContinuallyRan + 'static;
  fn into_task(&self) -> Self::Task;
}

#[derive(Clone)]
pub(crate) struct TestRequest {
  pub(crate) calls: Arc<AtomicUsize>,
  pub(crate) should_error: bool,
}

#[derive(Debug)]
pub(crate) struct RequestError;

impl TestRequest {
  pub(crate) fn new(should_error: bool) -> (Self, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (Self { calls: calls.clone(), should_error }, calls)
  }
}

impl RequestNotableCosigns for TestRequest {
  type Error = RequestError;

  fn request_notable_cosigns(
    &self,
    _global_session: [u8; 32],
  ) -> impl Send + core::future::Future<Output = Result<(), Self::Error>> {
    let calls = self.calls.clone();
    let should_error = self.should_error;
    async move {
      calls.fetch_add(1, Ordering::SeqCst);
      if should_error {
        Err(RequestError)
      } else {
        Ok(())
      }
    }
  }
}
