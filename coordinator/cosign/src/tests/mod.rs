use std::{
  collections::HashMap,
  sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
  },
  time::{Duration, Instant},
};

use rand_core::{RngCore, CryptoRng};
use rand::{Rng as _, seq::SliceRandom as _};

use serai_client_serai::{
  abi::{
    self,
    primitives::{
      self as serai_primitives, crypto::*, address::SeraiAddress, network_id::*, balance::*,
      validator_sets::*, test_helpers::*,
    },
    validator_sets::Event,
  },
  Serai,
};

use serai_db::{DbTxn, Db as _, MemDb};
use serai_task::{
  ContinuallyRan, Task,
  test_helpers::{IntoTask, TaskTest, IntoMockSerai},
  impl_serai_task_test_struct,
};
use serai_cosign_types::{
  SignedCosign,
  test_helpers::{random_cosign_intent, random_cosign, sign_cosign},
};

pub use serai_mock_rpc::{
  block_events_fuzzer::BlockEventsFuzzer, new_test_rng, test_helpers::random_subset,
};

pub(crate) use crate::test_helpers::random_global_cosigning_session_id;

use crate::RequestNotableCosigns;

/// Generate a random non-empty subset of [`ExternalValidatorSet`]s for testing.
pub(crate) fn random_external_validator_sets<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> Vec<ExternalValidatorSet> {
  let mut networks = all_external_networks();
  random_subset(rng, &mut networks);
  networks
    .iter()
    .map(|&network| ExternalValidatorSet { network, session: Session(rng.next_u32()) })
    .collect()
}

mod intend;
mod evaluator;
mod delay;
mod cosigning;
mod full_stack;

#[derive(Clone)]
struct TestRequest {
  calls: Arc<AtomicUsize>,
  should_error: bool,
}

#[derive(Debug)]
struct RequestError;

impl TestRequest {
  fn new(should_error: bool) -> (Self, Arc<AtomicUsize>) {
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
