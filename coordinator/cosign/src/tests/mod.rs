#[cfg(test)]
mod intend;

#[cfg(test)]
mod evaluator;

#[cfg(test)]
mod delay;

#[cfg(test)]
mod cosigning;

#[cfg(test)]
mod types;

use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
};

use serai_cosign_types::{COSIGN_CONTEXT, Cosign, SignedCosign};
use serai_task::ContinuallyRan;

use crate::RequestNotableCosigns;

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

pub(crate) fn sr25519_fixture() -> schnorrkel::Keypair {
  schnorrkel::MiniSecretKey::from_bytes(&[0xff; 32])
    .expect("fixed seed should be valid")
    .expand_to_keypair(schnorrkel::ExpansionMode::Ed25519)
}

pub(crate) fn sign_cosign(cosign: Cosign, keypair: &schnorrkel::Keypair) -> SignedCosign {
  SignedCosign {
    cosign: cosign.clone(),
    signature: keypair.sign_simple(COSIGN_CONTEXT, &cosign.signature_message()).to_bytes(),
  }
}
