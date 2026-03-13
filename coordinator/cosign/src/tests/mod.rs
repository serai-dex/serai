#[cfg(test)]
mod intend;

#[cfg(test)]
mod evaluator;

#[cfg(test)]
mod delay;

#[cfg(test)]
mod cosigning;

#[cfg(test)]
mod full_stack;

use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
};

use serai_shim_rpc::{SeraiShimRpc, ShimState};
use serai_client_serai::Serai;
pub(crate) use serai_test_task::{IntoTask, TaskTest};

use crate::RequestNotableCosigns;

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

/// Create a [`SeraiShimRpc`] and a [`Arc<Serai>`] to use it.
async fn setup_shim_serai() -> (SeraiShimRpc, Arc<Serai>) {
  let shim_serai = SeraiShimRpc::start(ShimState::default()).await;
  let serai = Arc::new(Serai::new(shim_serai.url()).unwrap());
  (shim_serai, serai)
}
