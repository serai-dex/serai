#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use std::collections::HashMap;

use borsh::{BorshSerialize, BorshDeserialize};

use blake2::{
  digest::{typenum::U32, Digest as _},
  Blake2b,
};
use dkg::Participant;

use serai_client_serai::abi::{
  primitives::{
    BitVec,
    network_id::ExternalNetworkId,
    validator_sets::{Session, ExternalValidatorSet, KeyShares, SlashReport},
    crypto::{Signature, KeyPair},
    address::SeraiAddress,
    instructions::SignedBatch,
  },
  Transaction,
};

use serai_db::Transaction as DbTxn;

mod canonical;
pub use canonical::CanonicalEventStream;
use canonical::last_indexed_batch_id;
mod ephemeral;
pub use ephemeral::EphemeralEventStream;

mod set_keys;
pub use set_keys::SetKeysTask;
mod publish_batch;
pub use publish_batch::PublishBatchTask;
mod publish_slash_report;
pub use publish_slash_report::PublishSlashReportTask;

/// The information for a new set.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
#[borsh(init = init_participant_indexes)]
pub struct NewSetInformation {
  /// The set.
  pub set: ExternalValidatorSet,
  /// The Serai block which declared it.
  pub serai_block: [u8; 32],
  /// The threshold to use.
  pub threshold: u16,
  /// The validators, with the amount of key shares they have.
  pub validators: Vec<(SeraiAddress, u16)>,
  /// The eVRF public keys.
  ///
  /// This will have the necessary copies of the keys proper for each validator's weight,
  /// accordingly syncing up with `participant_indexes`.
  pub evrf_public_keys: Vec<([u8; 32], Vec<u8>)>,
  /// The participant indexes, indexed by their validator.
  #[borsh(skip)]
  pub participant_indexes: HashMap<SeraiAddress, Vec<Participant>>,
  /// The validators, indexed by their participant indexes.
  #[borsh(skip)]
  pub participant_indexes_reverse_lookup: HashMap<Participant, SeraiAddress>,
}

impl NewSetInformation {
  fn init_participant_indexes(&mut self) {
    let mut next_i = 1;
    self.participant_indexes = HashMap::with_capacity(self.validators.len());
    self.participant_indexes_reverse_lookup = HashMap::with_capacity(self.validators.len());
    for (validator, weight) in &self.validators {
      let mut these_is = Vec::with_capacity((*weight).into());
      for _ in 0 .. *weight {
        let this_i = Participant::new(next_i).unwrap();
        next_i += 1;

        these_is.push(this_i);
        self.participant_indexes_reverse_lookup.insert(this_i, *validator);
      }
      self.participant_indexes.insert(*validator, these_is);
    }
  }

  /// Create a new [`NewSetInformation`].
  pub fn new(
    set: ExternalValidatorSet,
    serai_block: [u8; 32],
    threshold: u16,
    validators: Vec<(SeraiAddress, u16)>,
    evrf_public_keys: Vec<([u8; 32], Vec<u8>)>,
  ) -> Self {
    let mut result = Self {
      set,
      serai_block,
      threshold,
      validators,
      evrf_public_keys,
      participant_indexes: Default::default(),
      participant_indexes_reverse_lookup: Default::default(),
    };
    result.init_participant_indexes();
    result
  }
}

impl NewSetInformation {
  /// The hash to use for the genesis of the corresponding Tributary.
  pub fn tributary_genesis(&self) -> [u8; 32] {
    // This MUST only hash data completely deterministic to the Substrate blockchain.
    Blake2b::<U32>::digest(borsh::to_vec(self).unwrap()).into()
  }
}

mod _public_db {
  use super::*;

  serai_db::channel!(
    CoordinatorSubstrate {
      // Canonical messages to send to the processor
      Canonical: (network: ExternalNetworkId) -> messages::substrate::CoordinatorMessage,

      // Relevant new set, from an ephemeral event stream
      NewSet: () -> NewSetInformation,
      // Potentially relevant sign slash report, from an ephemeral event stream
      SignSlashReport: (set: ExternalValidatorSet) -> (),

      // Signed batches to publish onto the Serai network
      SignedBatches: (network: ExternalNetworkId) -> SignedBatch,
    }
  );

  serai_db::schema!(
    CoordinatorSubstrate {
      // Keys to set on the Serai network
      Keys: (network: ExternalNetworkId) -> (Session, Transaction),
      // Slash reports to publish onto the Serai network
      SlashReports: (network: ExternalNetworkId) -> (Session, Transaction),
    }
  );
}

/// The canonical event stream.
pub struct Canonical;
impl Canonical {
  pub(crate) fn send(
    txn: &mut (impl Send + DbTxn),
    network: ExternalNetworkId,
    msg: &messages::substrate::CoordinatorMessage,
  ) {
    _public_db::Canonical::send(txn, network, msg);
  }
  /// Try to receive a canonical event, returning `None` if there is none to receive.
  pub fn try_recv(
    txn: &mut (impl Send + DbTxn),
    network: ExternalNetworkId,
  ) -> Option<messages::substrate::CoordinatorMessage> {
    _public_db::Canonical::try_recv(txn, network)
  }
}

/// The channel for new set events emitted by an ephemeral event stream.
pub struct NewSet;
impl NewSet {
  pub(crate) fn send(txn: &mut (impl Send + DbTxn), msg: &NewSetInformation) {
    _public_db::NewSet::send(txn, msg);
  }
  /// Try to receive a new set's information, returning `None` if there is none to receive.
  pub fn try_recv(txn: &mut (impl Send + DbTxn)) -> Option<NewSetInformation> {
    _public_db::NewSet::try_recv(txn)
  }
}

/// The channel for notifications to sign a slash report, as emitted by an ephemeral event stream.
///
/// These notifications MAY be for irrelevant validator sets. The only guarantee is the
/// notifications for all relevant validator sets will be included.
pub struct SignSlashReport;
impl SignSlashReport {
  pub(crate) fn send(txn: &mut (impl Send + DbTxn), set: ExternalValidatorSet) {
    _public_db::SignSlashReport::send(txn, set, &());
  }
  /// Try to receive a notification to sign a slash report, returning `None` if there is none to
  /// receive.
  pub fn try_recv(txn: &mut (impl Send + DbTxn), set: ExternalValidatorSet) -> Option<()> {
    _public_db::SignSlashReport::try_recv(txn, set)
  }
}

/// The keys to set on Serai.
pub struct Keys;
impl Keys {
  /// Set the keys to report for a validator set.
  ///
  /// This only saves the most recent keys as only a single session is eligible to have its keys
  /// reported at once.
  pub fn set(
    txn: &mut (impl Send + DbTxn),
    set: ExternalValidatorSet,
    key_pair: KeyPair,
    signature_participants: BitVec<{ KeyShares::MAX_PER_SET_U64 }>,
    signature: Signature,
  ) {
    // If we have a more recent pair of keys, don't write this historic one
    if let Some((existing_session, _)) = _public_db::Keys::get(txn, set.network) {
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
    _public_db::Keys::set(txn, set.network, &(set.session, tx));
  }
  pub(crate) fn take(
    txn: &mut (impl Send + DbTxn),
    network: ExternalNetworkId,
  ) -> Option<(Session, Transaction)> {
    _public_db::Keys::take(txn, network)
  }
}

/// The signed batches to publish onto Serai.
pub struct SignedBatches;
impl SignedBatches {
  /// Send a `SignedBatch` to publish onto Serai.
  pub fn send(txn: &mut (impl Send + DbTxn), batch: &SignedBatch) {
    _public_db::SignedBatches::send(txn, batch.batch.network(), batch);
  }
  pub(crate) fn try_recv(
    txn: &mut (impl Send + DbTxn),
    network: ExternalNetworkId,
  ) -> Option<SignedBatch> {
    _public_db::SignedBatches::try_recv(txn, network)
  }
}

/// The slash reports to publish onto Serai.
pub struct SlashReports;
impl SlashReports {
  /// Set the slashes to report for a validator set.
  ///
  /// This only saves the most recent slashes as only a single session is eligible to have its
  /// slashes reported at once.
  pub fn set(
    txn: &mut (impl Send + DbTxn),
    set: ExternalValidatorSet,
    slash_report: SlashReport,
    signature: Signature,
  ) {
    // If we have a more recent slash report, don't write this historic one
    if let Some((existing_session, _)) = _public_db::SlashReports::get(txn, set.network) {
      if existing_session.0 >= set.session.0 {
        return;
      }
    }

    let tx = serai_client_serai::ValidatorSets::report_slashes(set, slash_report, signature);
    _public_db::SlashReports::set(txn, set.network, &(set.session, tx));
  }
  pub(crate) fn take(
    txn: &mut (impl Send + DbTxn),
    network: ExternalNetworkId,
  ) -> Option<(Session, Transaction)> {
    _public_db::SlashReports::take(txn, network)
  }
}
