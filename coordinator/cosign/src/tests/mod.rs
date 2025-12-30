#[cfg(test)]
mod intend;

#[cfg(test)]
mod delay;

use serai_task::ContinuallyRan;

pub(crate) struct Test;
impl Test {
  pub(crate) async fn assert_task_run_and_check_progress(
    task: &mut impl ContinuallyRan,
    made_progress: bool,
  ) {
    assert_eq!(task.run_iteration().await.unwrap(), made_progress);
  }

  pub(crate) async fn assert_task_failed_with(task: &mut impl ContinuallyRan, error: &str) {
    let err = task.run_iteration().await.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(err_str.contains(error), "{err_str}");
  }
}

pub(crate) trait IntoTask {
  type Task: ContinuallyRan + 'static;
  fn into_task(&self) -> Self::Task;
}
