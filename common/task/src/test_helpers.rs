//! Common test utilities for [`ContinuallyRan`] tasks.

use crate::ContinuallyRan;

/// Test helpers for asserting task iteration behavior.
pub struct TaskTest;

impl TaskTest {
  /// Assert that a task iteration succeeds and returns the expected progress value.
  pub async fn task_runs_once_and_matches_progress<T: ContinuallyRan>(
    task: &mut T,
    made_progress: bool,
  ) {
    serai_env::ensure_logger();
    serai_env::debug!("running task once: {}", core::any::type_name::<T>());
    assert_eq!(task.run_iteration().await.unwrap(), made_progress);
  }

  /// Assert that a task iteration panics with a message containing the given string.
  // TODO: Replace this with typed errors.
  pub async fn task_runs_and_panics_with<T: ContinuallyRan>(task: &mut T, error: &str) {
    serai_env::ensure_logger();
    serai_env::debug!("running task (expecting panic): {}", core::any::type_name::<T>());
    use futures::future::FutureExt as _;
    let result = core::panic::AssertUnwindSafe(task.run_iteration()).catch_unwind().await;
    match result {
      Ok(res) => {
        panic!("expected task to panic but it returned: {res:?}");
      }
      Err(panic) => {
        let msg = panic
          .downcast_ref::<&str>()
          .copied()
          .or_else(|| panic.downcast_ref::<String>().map(alloc::string::String::as_str))
          .unwrap_or("<non-string panic payload>");
        assert!(msg.contains(error), "panic message did not contain '{error}': {msg}");
      }
    }
  }

  /// Assert that a task iteration fails with an error containing the given string.
  // TODO: Replace this with typed errors.
  pub async fn task_runs_and_fails_with<T: ContinuallyRan>(task: &mut T, error: &str) {
    serai_env::ensure_logger();
    serai_env::debug!("running task (expecting failure): {}", core::any::type_name::<T>());
    let err = task.run_iteration().await.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(err_str.contains(error), "{err_str}");
  }
}

use core::future::Future;
extern crate alloc;
use alloc::sync::Arc;

/// Shared state used by Serai task tests.
pub struct SeraiTaskTestState {
  /// Serai client used by the task under test.
  pub serai: Arc<serai_client_serai::Serai>,

  /// In-memory database used by the test.
  pub db: serai_db::MemDb,
}

/// Trait for test structs that can be built from Serai test state.
pub trait SeraiTaskTestStruct: Sized {
  /// Build this test struct from the shared Serai test state.
  fn from_state(state: SeraiTaskTestState) -> Self;
}

/// Trait for test structs that can produce a [`ContinuallyRan`] task.
pub trait IntoTask: SeraiTaskTestStruct {
  /// The task type produced by this test struct.
  type Task: 'static + ContinuallyRan;

  /// Create the task from this test struct.
  fn task(&self) -> Self::Task;
}

use serai_client_serai::abi::primitives;

/// Trait for test structs that use a mock Serai RPC.
pub trait IntoMockSerai: IntoTask {
  /// Create a [`MockSeraiRpc`], this test struct, and its task.
  fn setup_mock_test() -> impl Future<Output = (serai_mock_rpc::MockSeraiRpc, Self)> + Send
  where
    Self: Sized + Send,
  {
    async {
      let (mock_serai, serai) = serai_mock_rpc::MockSeraiRpc::setup_mock_serai().await;
      let task_test = Self::from_state(SeraiTaskTestState { serai, db: serai_db::MemDb::new() });
      (mock_serai, task_test)
    }
  }

  /// Create a [`MockSeraiRpc`], this test struct, and its task.
  /// Feeds in a validator with its auxiliary keys included as event by default on genesis.
  fn setup_mock_test_with_validator(
    validator: primitives::address::SeraiAddress,
    keys: &[primitives::crypto::EmbeddedEllipticCurveKeys],
  ) -> impl Future<Output = (serai_mock_rpc::MockSeraiRpc, Self)> + Send
  where
    Self: Sized + Send,
  {
    async move {
      let (mock_serai, task_test) = Self::setup_mock_test().await;
      mock_serai
        .add_block_with_events(vec![keys
          .iter()
          .map(|key| {
            serai_mock_rpc::events::validator_sets::set_embedded_elliptic_curve_keys(
              validator, *key,
            )
          })
          .collect()])
        .await;
      (mock_serai, task_test)
    }
  }
}

/// Implements [`SeraiTaskTestStruct`] for a struct with `serai` and `db` fields.
///
/// An optional second argument accepts additional `field: expr` pairs for structs
/// with extra fields beyond `serai` and `db`.
#[macro_export]
macro_rules! impl_serai_task_test_struct {
  ($ty:ty) => {
    impl $crate::test_helpers::SeraiTaskTestStruct for $ty {
      fn from_state(state: $crate::test_helpers::SeraiTaskTestState) -> Self {
        Self { serai: state.serai, db: state.db }
      }
    }
  };
  ($ty:ty, $($field:ident: $default:expr),+) => {
    impl $crate::test_helpers::SeraiTaskTestStruct for $ty {
      fn from_state(state: $crate::test_helpers::SeraiTaskTestState) -> Self {
        Self { serai: state.serai, db: state.db, $($field: $default),+ }
      }
    }
  };
  ($ty:ty, { $($field:ident: $src:ident),+ $(,)? }) => {
    impl $crate::test_helpers::SeraiTaskTestStruct for $ty {
      fn from_state(state: $crate::test_helpers::SeraiTaskTestState) -> Self {
        Self { $($field: state.$src),+ }
      }
    }
  };
}
