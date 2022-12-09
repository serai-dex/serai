use std::{
  marker::PhantomData,
  time::{Duration, Instant},
  collections::HashMap,
};

use futures::{FutureExt, future};
use tokio::time::sleep;

use crate::{
  time::CanonicalInstant,
  Step,
  ext::{RoundNumber, Network},
};

pub(crate) struct RoundData<N: Network> {
  _network: PhantomData<N>,
  pub(crate) number: RoundNumber,
  pub(crate) start_time: CanonicalInstant,
  pub(crate) step: Step,
  pub(crate) timeouts: HashMap<Step, Instant>,
}

impl<N: Network> RoundData<N> {
  pub(crate) fn new(number: RoundNumber, start_time: CanonicalInstant) -> Self {
    RoundData {
      _network: PhantomData,
      number,
      start_time,
      step: Step::Propose,
      timeouts: HashMap::new(),
    }
  }

  fn timeout(&self, step: Step) -> CanonicalInstant {
    let adjusted_block = N::BLOCK_PROCESSING_TIME * (self.number.0 + 1);
    let adjusted_latency = N::LATENCY_TIME * (self.number.0 + 1);
    let offset = Duration::from_secs(
      (match step {
        Step::Propose => adjusted_block + adjusted_latency,
        Step::Prevote => adjusted_block + (2 * adjusted_latency),
        Step::Precommit => adjusted_block + (3 * adjusted_latency),
      })
      .into(),
    );
    self.start_time + offset
  }

  pub(crate) fn end_time(&self) -> CanonicalInstant {
    self.timeout(Step::Precommit)
  }

  pub(crate) fn set_timeout(&mut self, step: Step) {
    let timeout = self.timeout(step).instant();
    self.timeouts.entry(step).or_insert(timeout);
  }

  // Poll all set timeouts, returning the Step whose timeout has just expired
  pub(crate) async fn timeout_future(&self) -> Step {
    let timeout_future = |step| {
      let timeout = self.timeouts.get(&step).copied();
      (async move {
        if let Some(timeout) = timeout {
          sleep(timeout.saturating_duration_since(Instant::now())).await;
        } else {
          future::pending::<()>().await;
        }
        step
      })
      .fuse()
    };
    let propose_timeout = timeout_future(Step::Propose);
    let prevote_timeout = timeout_future(Step::Prevote);
    let precommit_timeout = timeout_future(Step::Precommit);
    futures::pin_mut!(propose_timeout, prevote_timeout, precommit_timeout);

    futures::select_biased! {
      step = propose_timeout => step,
      step = prevote_timeout => step,
      step = precommit_timeout => step,
    }
  }
}
