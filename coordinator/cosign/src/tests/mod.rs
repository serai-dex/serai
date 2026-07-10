use std::{
  collections::HashMap,
  sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, LazyLock,
  },
  time::{Duration, Instant},
};

use rand_core::{RngCore, CryptoRng, OsRng};
use rand::{Rng as _, seq::SliceRandom as _};

use serai_client_serai::{
  abi::{
    primitives::{
      crypto::*, address::SeraiAddress, network_id::*, balance::*, validator_sets::*,
      test_helpers::*,
    },
    validator_sets::Event,
  },
  Serai,
};

use serai_db::{Transaction as _, Db as _, MemDb};
use serai_task::{
  ContinuallyRan as _,
  test_helpers::{IntoTask, TaskTest},
};
use serai_cosign_types::tests::{
  random_external_network_id, random_global_session, random_cosign_intent, random_cosign,
  sign_cosign,
};

use serai_shim_rpc::{*, event_fuzzer::*};

use crate::{GlobalSession, RequestNotableCosigns};

mod intend;
mod evaluator;
mod delay;
mod cosigning;
mod full_stack;

static INIT_LOGGER: LazyLock<()> = LazyLock::new(|| {
  serai_env::init_logger();
});

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

/// Create a [`SeraiShimRpc`] and an [`Arc<Serai>`] to use it.
async fn setup_shim_serai() -> (SeraiShimRpc, Arc<Serai>) {
  let shim_serai = SeraiShimRpc::start(ShimState::default()).await;
  let serai = Arc::new(Serai::new(shim_serai.url()).unwrap());
  (shim_serai, serai)
}

fn default_test_validator_set() -> ExternalValidatorSet {
  ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) }
}
fn random_validator_set<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalValidatorSet {
  ExternalValidatorSet {
    network: random_external_network_id(rng),
    session: Session(rng.next_u32()),
  }
}

/// Build a single-network [`GlobalSession`] from the given components.
fn build_global_session(
  set: ExternalValidatorSet,
  public: Public,
  stake: u64,
  start_block_number: u64,
) -> GlobalSession {
  GlobalSession {
    start_block_number,
    sets: vec![set],
    keys: HashMap::from([(set.network, public)]),
    stakes: HashMap::from([(set.network, stake)]),
    total_stake: stake,
  }
}
