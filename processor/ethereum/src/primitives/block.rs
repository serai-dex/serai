use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Secp256k1};

use serai_client::networks::ethereum::Address;

use primitives::{ReceivedOutput, EventualityTracker};

use ethereum_router::{InInstruction as EthereumInInstruction, Executed};

use crate::{output::Output, transaction::Eventuality};

// We interpret 32-block Epochs as singular blocks.
// There's no reason for further accuracy when these will all finalize at the same time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Epoch {
  // The hash of the block which ended the prior Epoch.
  pub(crate) prior_end_hash: [u8; 32],
  // The hash of the last block within this Epoch.
  pub(crate) end_hash: [u8; 32],
}

impl primitives::BlockHeader for Epoch {
  fn id(&self) -> [u8; 32] {
    self.end_hash
  }
  fn parent(&self) -> [u8; 32] {
    self.prior_end_hash
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct FullEpoch {
  pub(crate) epoch: Epoch,
  pub(crate) instructions: Vec<EthereumInInstruction>,
  pub(crate) executed: Vec<Executed>,
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

  fn scan_for_outputs_unordered(
    &self,
    latest_active_key: Self::Key,
    key: Self::Key,
  ) -> Vec<Self::Output> {
    // Only return these outputs for the latest key
    if latest_active_key != key {
      return vec![];
    }

    // Associate all outputs with the latest active key
    // We don't associate these with the current key within the SC as that'll cause outputs to be
    // marked for forwarding if the SC is delayed to actually rotate
    self.instructions.iter().cloned().map(|instruction| Output { key, instruction }).collect()
  }

  #[allow(clippy::type_complexity)]
  fn check_for_eventuality_resolutions(
    &self,
    eventualities: &mut EventualityTracker<Self::Eventuality>,
  ) -> HashMap<
    <Self::Output as ReceivedOutput<Self::Key, Self::Address>>::TransactionId,
    Self::Eventuality,
  > {
    let mut res = HashMap::new();
    for executed in &self.executed {
      let Some(expected) =
        eventualities.active_eventualities.remove(executed.nonce().to_le_bytes().as_slice())
      else {
        continue;
      };
      assert_eq!(
        executed,
        &expected.0,
        "Router emitted distinct event for nonce {}",
        executed.nonce()
      );
      /*
        The transaction ID is used to determine how internal outputs from this transaction should
        be handled (if they were actually internal or if they were just to an internal address).
        The Ethereum integration doesn't have internal addresses, and this transaction wasn't made
        by Serai. It was simply authorized by Serai yet may or may not be associated with other
        actions we don't want to flag as our own.

        Accordingly, we set the transaction ID to the nonce. This is unique barring someone finding
        the preimage which hashes to this nonce, and won't cause any other data to be associated.
      */
      let mut tx_id = [0; 32];
      tx_id[.. 8].copy_from_slice(executed.nonce().to_le_bytes().as_slice());
      res.insert(tx_id, expected);
    }
    res
  }
}
