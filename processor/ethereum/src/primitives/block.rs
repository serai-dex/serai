use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Secp256k1};

use serai_client::networks::ethereum::Address;

use primitives::{ReceivedOutput, EventualityTracker};
use crate::{output::Output, transaction::Eventuality};

// We interpret 32-block Epochs as singular blocks.
// There's no reason for further accuracy when these will all finalize at the same time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Epoch {
  // The hash of the block which ended the prior Epoch.
  pub(crate) prior_end_hash: [u8; 32],
  // The first block number within this Epoch.
  pub(crate) start: u64,
  // The hash of the last block within this Epoch.
  pub(crate) end_hash: [u8; 32],
  // The monotonic time for this Epoch.
  pub(crate) time: u64,
}

impl Epoch {
  // The block number of the last block within this epoch.
  fn end(&self) -> u64 {
    self.start + 31
  }
}

impl primitives::BlockHeader for Epoch {
  fn id(&self) -> [u8; 32] {
    self.end_hash
  }
  fn parent(&self) -> [u8; 32] {
    self.prior_end_hash
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct FullEpoch {
  epoch: Epoch,
}

impl primitives::Block for FullEpoch {
  type Header = Epoch;

  type Key = <Secp256k1 as Ciphersuite>::G;
  type Address = Address;
  type Output = Output;
  type Eventuality = Eventuality;

  fn id(&self) -> [u8; 32] {
    self.epoch.end_hash
  }

  fn scan_for_outputs_unordered(&self, key: Self::Key) -> Vec<Self::Output> {
    todo!("TODO")
  }

  #[allow(clippy::type_complexity)]
  fn check_for_eventuality_resolutions(
    &self,
    eventualities: &mut EventualityTracker<Self::Eventuality>,
  ) -> HashMap<
    <Self::Output as ReceivedOutput<Self::Key, Self::Address>>::TransactionId,
    Self::Eventuality,
  > {
    todo!("TODO")
  }
}
