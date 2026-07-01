#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use blake2::{digest::typenum::U32, Digest as _, Blake2b};
use borsh::{BorshSerialize, BorshDeserialize};

use serai_client_serai::abi::{
  primitives::{
    BitVec,
    network_id::ExternalNetworkId,
    validator_sets::{Session, ExternalValidatorSet, KeyShares, SlashReport},
    crypto::{Signature, KeyPair},
    instructions::SignedBatch,
  },
  Transaction,
};

use serai_db::*;

mod canonical;
pub use canonical::CanonicalEventStream;
mod ephemeral;
pub use ephemeral::EphemeralEventStream;

mod set_keys;
use serai_tributary_types::TributaryValidatorSet;
pub use set_keys::SetKeysTask;
mod publish_batch;
pub use publish_batch::PublishBatchTask;
mod publish_slash_report;
pub use publish_slash_report::PublishSlashReportTask;

/// Test helpers and fixtures.
#[cfg(test)]
pub mod tests;

#[cfg(any(test, feature = "test-helpers"))]
/// Test helpers and fixtures.
pub mod test_helpers;

/// The information for a new set.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TributaryValidatorSetInfo {
  /// The set.
  pub set: ExternalValidatorSet,
  /// The Serai block which declared it.
  pub serai_block: [u8; 32],
  /// The time of the block which declared it, in seconds since the epoch.
  pub declaration_time: u64,
  /// The structure of validators viewed by the coordinator and processor perspectives
  /// Each entry contains auxiliary keys (substrate and network) with weight.
  /// Accordingly syncs up participant indexes and reverse lookup fields.
  pub tributary_validator_set: TributaryValidatorSet,
}

impl TributaryValidatorSetInfo {
  /// The hash to use for the genesis of the corresponding Tributary.
  pub fn tributary_genesis(&self) -> [u8; 32] {
    // This MUST only hash data completely deterministic to the Substrate blockchain.
    Blake2b::<U32>::digest(borsh::to_vec(self).unwrap()).into()
  }
}

mod _public_db {
  use super::*;

  db_channel!(
    CoordinatorSubstrateChannels {
      // Canonical messages to send to the processor
      Canonical: (network: ExternalNetworkId) -> messages::substrate::CoordinatorMessage,

      // Relevant new set, from an ephemeral event stream
      EphemeralNewDecidedSet: () -> TributaryValidatorSetInfo,
      // Potentially relevant sign slash report notification, after an ephemeral event stream
      // sees an Accepted Handover event for a given session.
      EphemeralSetHasToSignSlashReport: (set: ExternalValidatorSet) -> (),

      // Signed batches from the processor to publish onto the Serai network
      NetworksProcessorSignedBatches: (network: ExternalNetworkId) -> SignedBatch,
    }
  );

  create_db!(
    CoordinatorSubstrate {
      // Keys to set on the Serai network
      NetworksSetKeysTransaction: (network: ExternalNetworkId) -> (Session, Transaction),
      // Slash reports to publish onto the Serai network
      NetworksSlashReportsTransaction: (network: ExternalNetworkId) -> (Session, Transaction),
    }
  );
}

/// The canonical event stream.
pub struct Canonical;
impl Canonical {
  pub(crate) fn send(
    txn: &mut impl DbTxn,
    network: ExternalNetworkId,
    msg: &messages::substrate::CoordinatorMessage,
  ) {
    _public_db::Canonical::send(txn, network, msg);
  }
  /// Try to receive a canonical event, returning `None` if there is none to receive.
  pub fn try_recv(
    txn: &mut impl DbTxn,
    network: ExternalNetworkId,
  ) -> Option<messages::substrate::CoordinatorMessage> {
    _public_db::Canonical::try_recv(txn, network)
  }
}

/// The channel for new set events emitted by an ephemeral event stream.
pub struct EphemeralNewDecidedSet;
impl EphemeralNewDecidedSet {
  pub(crate) fn send(txn: &mut impl DbTxn, msg: &TributaryValidatorSetInfo) {
    _public_db::EphemeralNewDecidedSet::send(txn, msg);
  }
  /// Try to receive a new set's information, returning `None` if there is none to receive.
  pub fn try_recv(txn: &mut impl DbTxn) -> Option<TributaryValidatorSetInfo> {
    _public_db::EphemeralNewDecidedSet::try_recv(txn)
  }
}

/// The channel for notifications to sign a slash report, as emitted by an ephemeral event stream.
///
/// These notifications MAY be for irrelevant validator sets. The only guarantee is the
/// notifications for all relevant validator sets will be included.
pub struct EphemeralSetHasToSignSlashReport;
impl EphemeralSetHasToSignSlashReport {
  pub(crate) fn send(txn: &mut impl DbTxn, set: ExternalValidatorSet) {
    _public_db::EphemeralSetHasToSignSlashReport::send(txn, set, &());
  }
  /// Try to receive a notification to sign a slash report, returning `None` if there is none to
  /// receive.
  pub fn try_recv(txn: &mut impl DbTxn, set: ExternalValidatorSet) -> Option<()> {
    _public_db::EphemeralSetHasToSignSlashReport::try_recv(txn, set)
  }
}

/// The keys to set on Serai.
pub struct NetworksSetKeysTransaction;
impl NetworksSetKeysTransaction {
  /// Set the keys to report for a validator set.
  ///
  /// This only saves the most recent keys as only a single session is eligible to have its keys
  /// reported at once.
  pub fn set(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    key_pair: KeyPair,
    signature_participants: BitVec<{ KeyShares::MAX_PER_SET_U64 }>,
    signature: Signature,
  ) {
    // If we have a more recent pair of keys, don't write this historic one
    if let Some((existing_session, _)) =
      _public_db::NetworksSetKeysTransaction::get(txn, set.network)
    {
      if existing_session.0 >= set.session.0 {
        return;
      }
    }

    let tx = serai_client_serai::ValidatorSets::set_keys(
      set.network,
      key_pair,
      signature_participants,
      signature,
    );
    _public_db::NetworksSetKeysTransaction::set(txn, set.network, &(set.session, tx));
  }
  pub(crate) fn take(
    txn: &mut impl DbTxn,
    network: ExternalNetworkId,
  ) -> Option<(Session, Transaction)> {
    _public_db::NetworksSetKeysTransaction::take(txn, network)
  }
}

/// The signed batches to publish onto Serai.
pub struct NetworksProcessorSignedBatches;
impl NetworksProcessorSignedBatches {
  /// Send a `SignedBatch` to publish onto Serai.
  pub fn send(txn: &mut impl DbTxn, batch: &SignedBatch) {
    _public_db::NetworksProcessorSignedBatches::send(txn, batch.batch.network(), batch);
  }
  pub(crate) fn try_recv(txn: &mut impl DbTxn, network: ExternalNetworkId) -> Option<SignedBatch> {
    _public_db::NetworksProcessorSignedBatches::try_recv(txn, network)
  }
}

/// The slash reports to publish onto Serai.
pub struct NetworksSlashReports;
impl NetworksSlashReports {
  /// Set the slashes to report for a validator set.
  ///
  /// This only saves the most recent slashes as only a single session is eligible to have its
  /// slashes reported at once.
  pub fn set(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    slash_report: SlashReport,
    signature: Signature,
  ) {
    // If we have a more recent slash report, don't write this historic one
    if let Some((existing_session, _)) =
      _public_db::NetworksSlashReportsTransaction::get(txn, set.network)
    {
      if existing_session.0 >= set.session.0 {
        return;
      }
    }

    let tx = serai_client_serai::ValidatorSets::report_slashes(set, slash_report, signature);
    _public_db::NetworksSlashReportsTransaction::set(txn, set.network, &(set.session, tx));
  }
  pub(crate) fn take(
    txn: &mut impl DbTxn,
    network: ExternalNetworkId,
  ) -> Option<(Session, Transaction)> {
    _public_db::NetworksSlashReportsTransaction::take(txn, network)
  }
}
