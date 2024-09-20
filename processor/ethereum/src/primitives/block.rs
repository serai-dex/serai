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
    let mut outputs: Vec<_> = self
      .instructions
      .iter()
      .cloned()
      .map(|instruction| Output::Output { key, instruction })
      .collect();

    /*
      The scanner requires a change output be associated with every Eventuality that came from
      fulfilling payments, unless said Eventuality descends from an Eventuality meeting that
      requirement from the same fulfillment. This ensures we have a fully populated Eventualities
      set by the time we process the block which has an Eventuality.

      Accordingly, for any block with an Eventuality completion, we claim there's a Change output
      so that the block is flagged. Ethereum doesn't actually have Change outputs, yet the scanner
      won't report them to Substrate, and the Smart Contract scheduler will drop any/all outputs
      passed to it (handwaving their balances as present within the Smart Contract).
    */
    if !self.executed.is_empty() {
      outputs.push(Output::Eventuality { key, nonce: self.executed.first().unwrap().nonce() });
    }

    outputs
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
        The Ethereum integration doesn't use internal addresses, and only uses internal outputs to
        flag a block as having an Eventuality. Those internal outputs will always be scanned, and
        while they may be dropped/kept by this ID, the scheduler will then always drop them.
        Accordingly, we have free reign as to what to set the transaction ID to.

        We set the ID to the nonce as it's the most helpful value and unique barring someone
        finding the premise for this as a hash.
      */
      let mut tx_id = [0; 32];
      tx_id[.. 8].copy_from_slice(executed.nonce().to_le_bytes().as_slice());
      res.insert(tx_id, expected);
    }
    res
  }
}
