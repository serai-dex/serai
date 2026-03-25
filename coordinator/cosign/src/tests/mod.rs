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

pub use std::{
  collections::HashMap,
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
  },
  time::{Duration, Instant},
};

pub use borsh::{BorshDeserialize, BorshSerialize};
pub use rand::{CryptoRng, Rng, RngCore, seq::SliceRandom};
pub use rand_core::OsRng;

pub use serai_db::{Db, DbTxn, MemDb};
pub use serai_shim_rpc::{*, event_fuzzer::*};
pub use serai_abi::validator_sets::Event;
pub use serai_client_serai::{
  Serai,
  abi::primitives::{
    address::SeraiAddress, balance::*, coin::*, crypto::*, instructions::*, network_id::*,
    validator_sets::*,
  },
};
pub use serai_task::{
  ContinuallyRan, Task,
  test_helpers::{IntoTask, TaskTest},
};
pub use serai_primitives::test_helpers::*;
pub use serai_cosign_types::{
  SignedCosign,
  tests::{sign_cosign, random_cosign, random_cosign_intent},
};

use crate::{GlobalSession, RequestNotableCosigns};

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
pub(crate) async fn setup_shim_serai() -> (SeraiShimRpc, Arc<Serai>) {
  let shim_serai = SeraiShimRpc::start(ShimState::default()).await;
  let serai = Arc::new(Serai::new(shim_serai.url()).unwrap());
  (shim_serai, serai)
}

pub use serai_cosign_types::tests::random_external_network_id;

/// For whe external validator set does not alter or affect the behavior of the functions being tested
/// this can be used just as a default value any time
pub(crate) fn default_test_validator_set() -> ExternalValidatorSet {
  ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) }
}
pub(crate) fn random_validator_set<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalValidatorSet {
  ExternalValidatorSet { network: random_external_network_id(rng), session: Session(rng.gen()) }
}

/// Build a single-network [`GlobalSession`] from the given components.
pub(crate) fn build_global_session(
  set: ExternalValidatorSet,
  public: Public,
  stake: u64,
  start_block_number: u64,
) -> GlobalSession {
  let mut keys = HashMap::new();
  keys.insert(set.network, public);
  let mut stakes = HashMap::new();
  stakes.insert(set.network, stake);
  GlobalSession { start_block_number, sets: vec![set], keys, stakes, total_stake: stake }
}
