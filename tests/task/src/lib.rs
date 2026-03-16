//! Common test utilities for `serai-task` [`ContinuallyRan`] tasks.

#![deny(missing_docs)]

use serai_task::ContinuallyRan;

/// Test helpers for asserting task iteration behavior.
pub struct TaskTest;

impl TaskTest {
  /// Assert that a task iteration succeeds and returns the expected progress value.
  pub async fn task_runs_once_and_matches_progress<T: ContinuallyRan>(
    task: &mut T,
    made_progress: bool,
  ) {
    serai_env::log::debug!("running task once: {}", core::any::type_name::<T>());
    assert_eq!(task.run_iteration().await.unwrap(), made_progress);
  }

  /// Assert that a task iteration fails with an error containing the given string.
  pub async fn task_runs_and_fails_with<T: ContinuallyRan>(task: &mut T, error: &str) {
    serai_env::log::debug!("running task (expecting failure): {}", core::any::type_name::<T>());
    let err = task.run_iteration().await.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(err_str.contains(error), "{err_str}");
  }
}

/// Trait for test structs that can produce a [`ContinuallyRan`] task.
pub trait IntoTask {
  /// The task type produced by this test struct.
  type Task: ContinuallyRan + 'static;
  /// Create the task from the current test state.
  fn into_task(&self) -> Self::Task;
}
