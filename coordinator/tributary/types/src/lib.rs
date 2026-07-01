#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

extern crate alloc;

use alloc::vec::Vec;
use serai_primitives::crypto::SeraiNetworksAuxiliaryKey;
use std_shims::collections::HashMap;
use dkg::Participant;

use borsh::{BorshSerialize, BorshDeserialize};

/// Test cases.
#[cfg(test)]
pub mod tests;

/// Utilities for testing tributary validators.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

pub(crate) const PARTICIPATION_THRESHOLD_NUMERATOR: u16 = 2;
pub(crate) const PARTICIPATION_THRESHOLD_DENOMINATOR: u16 = 3;

/// All of our topics on the tributary require 2/3rds participation, but also the eVRF DKG protocol.
pub fn required_participation(n: u16) -> u16 {
  const {
    assert!(PARTICIPATION_THRESHOLD_NUMERATOR < PARTICIPATION_THRESHOLD_DENOMINATOR);
  }
  // We promote to `u32` to perform the math so the multiplication doesn't overflow `u16`.
  u16::try_from(
    (u32::from(n) * u32::from(PARTICIPATION_THRESHOLD_NUMERATOR)) /
      u32::from(PARTICIPATION_THRESHOLD_DENOMINATOR) +
      1,
  )
  .unwrap()
}

/// Participant indexes are one-indexed yet array indexes are zero-indexed
pub(crate) fn participant_index_to_list_index(participant: Participant) -> Option<usize> {
  usize::from(u16::from(participant)).checked_sub(1)
}

/// A validator from a Serai's set_decided event, used for different signing protocols.
/// Stores the validator's NetworkId::Serai auxiliary key, and both NetworkId::External substrate
/// and network auxiliary keys with a weight.
#[derive(Clone, Hash, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct TributaryValidator {
  /// This validator's NetworkId::Serai auxiliary key bytes, used for identifying itself.
  pub serai_networks_auxiliary_key: [u8; 32],
  /// This validator's external network's Substrate auxiliary key bytes, used for the DKG eVRF
  /// protocol.
  pub networks_substrate_key: [u8; 32],
  /// This validator's network-specific auxiliary key byte array, used for the DKG eVRF protocol.
  pub networks_external_key: Vec<u8>,
  /// This validator's weight within the validator set.
  pub weight: u16,
}
impl TributaryValidator {
  /// Create a new [`TributaryValidator`].
  pub fn new(
    serai_networks_auxiliary_key: [u8; 32],
    networks_substrate_key: [u8; 32],
    networks_external_key: Vec<u8>,
    weight: u16,
  ) -> Self {
    Self { serai_networks_auxiliary_key, networks_substrate_key, networks_external_key, weight }
  }

  /// Get the [`SeraiNetworksAuxiliaryKey`] struct by this validator's
  /// NetworkId::Serai auxiliary key bytes.
  pub fn get_serai_networks_auxiliary_key(&self) -> SeraiNetworksAuxiliaryKey {
    SeraiNetworksAuxiliaryKey::from_bytes(self.serai_networks_auxiliary_key)
      // Serai blockchain invariant: [`TributaryValidator`] items are created from on-chain
      // set_decided events and auxiliary key events, expected to have valid auxiliary keys set
      .expect("validator had an invalid serai auxiliary key")
  }
}

/// A list of tributary validators, with their auxiliary keys and weights,
/// and the [`Participant`] indexes used for the DKG eVRF protocol are calculated and cached.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[borsh(init = init_participant_indexes)]
#[derive(Default)]
pub struct TributaryValidatorSet {
  /// The original, unchanged, list of tributary validators as given by the Serai blockchain's
  /// set_decided event.
  pub initial_tributary_validators: Vec<TributaryValidator>,
  /// Even though the set_decided event has different validator addresses and stakes, the ephemeral
  /// task mapped them to auxiliary keys not checking for duplicates, but given that multiple
  /// validators, on paper, may share auxiliary keys, that would mean `initial_tributary_validators`
  /// may contain items with equal serai auxiliary keys. We need to merge them and sum the weights.
  ///
  /// Stores the flattened list of tributary validators, now with unique serai auxiliary keys and
  /// summed weight.
  #[borsh(skip)]
  pub consensus_tributary_validators: Vec<TributaryValidator>,
  /// Participant indexes of the flattened validators list, keyed by each unique serai auxiliary
  /// key. Every validator has only one participant index, after flattening.
  #[borsh(skip)]
  pub(crate) consensus_participant_index: HashMap<SeraiNetworksAuxiliaryKey, Participant>,
  /// Total weight of all validators in the set.
  #[borsh(skip)]
  total_weight: u16,
  /// Threshold for the eVRF protocol, calculated as `(n * 2/3) + 1`.
  #[borsh(skip)]
  evrf_threshold: u16,
  /// The list of eVRF participant indexes, indexed by each unique eVRF key pair
  #[borsh(skip)]
  pub(crate) evrf_participant_indexes: HashMap<TributaryValidator, Vec<Participant>>,
  /// The eVRF key pairs, indexed by each of their eVRF participant indexes.
  #[borsh(skip)]
  pub(crate) evrf_participant_indexes_reverse_lookup: HashMap<Participant, TributaryValidator>,
  /// Cache of all initial tributary validator's substrate eVRF public keys, in original order.
  #[borsh(skip)]
  evrf_networks_substrate_keys: Vec<[u8; 32]>,
  /// Cache of all initial tributary validator's network's eVRF public keys, in original order.
  #[borsh(skip)]
  evrf_networks_external_keys: Vec<Vec<u8>>,
}
impl TributaryValidatorSet {
  /// Create a new `TributaryValidatorSet`, populate default cache values and populate the cache.
  pub fn new(validators: Vec<TributaryValidator>) -> Self {
    let mut new = Self {
      initial_tributary_validators: validators,
      consensus_tributary_validators: Vec::new(),
      evrf_participant_indexes: HashMap::new(),
      evrf_participant_indexes_reverse_lookup: HashMap::new(),
      consensus_participant_index: HashMap::new(),
      total_weight: 0,
      evrf_threshold: 0,
      evrf_networks_substrate_keys: Vec::new(),
      evrf_networks_external_keys: Vec::new(),
    };
    new.init_participant_indexes();
    new
  }

  /// Flatten `initial_tributary_validators` into `consensus_tributary_validators` (deduplicate by
  /// serai key, summing weights for duplicates), then sync up evrf and non-evrf participant indexes
  /// and reverse lookup caches.
  pub fn init_participant_indexes(&mut self) {
    let mut flattened_tributary_validators: Vec<TributaryValidator> =
      Vec::with_capacity(self.initial_tributary_validators.len());

    for i_tributary_validator in &self.initial_tributary_validators {
      let existing_match_found = flattened_tributary_validators.iter_mut().find(|v| {
        v.get_serai_networks_auxiliary_key().to_bytes() ==
          i_tributary_validator.serai_networks_auxiliary_key
      });

      match existing_match_found {
        Some(existing) => {
          // assumes can always add weight, expected panic on overflow. weight value comes
          // from serai
          existing.weight += i_tributary_validator.weight;
        }
        None => {
          flattened_tributary_validators.push(i_tributary_validator.clone());
        }
      }
    }
    self.consensus_tributary_validators = flattened_tributary_validators;

    let consensus_n = self.consensus_tributary_validators.len();
    self.consensus_participant_index = HashMap::with_capacity(consensus_n);

    for (next_participant_index, i_consensus_validator) in
      // Participants are one-indexed
      (1 ..).zip(self.consensus_tributary_validators.iter())
    {
      let i_validator_serai_networks_auxiliary_key =
        i_consensus_validator.get_serai_networks_auxiliary_key();

      let i_consensus_index = Participant::new(next_participant_index).unwrap();
      self
        .consensus_participant_index
        .insert(i_validator_serai_networks_auxiliary_key, i_consensus_index);
    }

    self.total_weight = u16::try_from(
      self.initial_tributary_validators.iter().map(|v| u32::from(v.weight)).sum::<u32>(),
    )
    .expect("total weight doesn't fit in u16");

    // At this point we don't handle invalid or duplicate keys, so use the original lists' len
    // so every validator will be assumed as different processors and all key shares will be
    // indexed as unique. The key_gen crate of the processor handles invalid keys during execution,
    // and duplicates (same or different validators that hold the same processor keys) will just
    // add more key shares that the private key owners can decrypt, so it will require each
    // validator's participation count for knowledge of the amount of key shares expected to be
    // signed by each.
    let n_evrf = self.initial_tributary_validators.len();
    self.evrf_threshold =
      required_participation(u16::try_from(n_evrf).expect("validator set size doesn't fit in u16"));

    // Participants are one-indexed
    let mut next_participant_index = 1;

    self.evrf_participant_indexes = HashMap::with_capacity(n_evrf);
    // Each Participant will show up #(weight) times, so the total amount of participants
    // will be equal to the total_weight
    self.evrf_participant_indexes_reverse_lookup =
      HashMap::with_capacity(self.total_weight().into());

    self.evrf_networks_substrate_keys = Vec::with_capacity(self.total_weight().into());
    self.evrf_networks_external_keys = Vec::with_capacity(self.total_weight().into());

    for i_tributary_validator in &self.initial_tributary_validators {
      let weight = i_tributary_validator.weight;

      let mut i_validator_evrf_participant_indexes = Vec::with_capacity(weight.into());
      for _ in 0 .. weight {
        let i_participant = Participant::new(next_participant_index).unwrap();
        next_participant_index += 1;

        i_validator_evrf_participant_indexes.push(i_participant);
        self
          .evrf_participant_indexes_reverse_lookup
          .insert(i_participant, i_tributary_validator.clone());

        self.evrf_networks_substrate_keys.push(i_tributary_validator.networks_substrate_key);
        self.evrf_networks_external_keys.push(i_tributary_validator.networks_external_key.clone());
      }
      self
        .evrf_participant_indexes
        .insert(i_tributary_validator.clone(), i_validator_evrf_participant_indexes);
    }
  }

  /// Try to get a [`TributaryValidator`] by their consensus participant index.
  pub fn get_tributary_validator_by_consensus_index(
    &self,
    participant: &Participant,
  ) -> Option<&TributaryValidator> {
    self.consensus_tributary_validators.get(participant_index_to_list_index(*participant)?)
  }

  /// Try to get a [`TributaryValidator`] by their eVRF participant index.
  pub fn get_tributary_validator_by_evrf_index(
    &self,
    participant: &Participant,
  ) -> Option<&TributaryValidator> {
    self.evrf_participant_indexes_reverse_lookup.get(participant)
  }

  /// Try to get a [`Participant`] consensus index by a given [`TributaryValidator`].
  pub fn get_consensus_index_by_tributary_validator(
    &self,
    tributary_validator: &TributaryValidator,
  ) -> Option<&Participant> {
    self.consensus_participant_index.get(&tributary_validator.get_serai_networks_auxiliary_key())
  }

  /// Try to get a [`Participant`] consensus index by a given NetworkId::Serai auxiliary key bytes.
  pub fn get_consensus_index_by_serai_auxiliary(
    &self,
    serai_auxiliary_bytes: [u8; 32],
  ) -> Option<&Participant> {
    self
      .consensus_participant_index
      .get(&SeraiNetworksAuxiliaryKey::from_bytes(serai_auxiliary_bytes).ok()?)
  }

  /// Try to get a [`Vec<Participant>`] list of evrf indexes by a given [`Participant`] consensus
  /// index, matching its position to its unique set of serai auxiliary + evrf keys + weight, and
  /// query its participant indexes.
  pub fn get_evrf_indexes_by_consensus_index(
    &self,
    participant: &Participant,
  ) -> Option<&Vec<Participant>> {
    let tributary_validator = self.get_tributary_validator_by_consensus_index(participant)?;
    self.evrf_participant_indexes.get(tributary_validator)
  }

  /// Iterate over all consensus tributary validators (validators after flattening), yielding each
  /// [`Participant`] index paired with its [`TributaryValidator`].
  pub fn consensus_participants(&self) -> impl Iterator<Item = (Participant, &TributaryValidator)> {
    self
      .consensus_tributary_validators
      .iter()
      .enumerate()
      .map(|(i, validator)| (Participant::new(u16::try_from(i + 1).unwrap()).unwrap(), validator))
  }

  /// Check if a [`Participant`] evrf index corresponds to a validator with the given
  /// NetworkId::Serai auxiliary key bytes on the consensus tributary validators list
  /// by getting the unique set of serai auxiliary + evrf keys + weight cached by the evrf index
  pub fn get_evrf_index_matches_serai_auxiliary(
    &self,
    participant: &Participant,
    serai_auxiliary: &[u8; 32],
  ) -> bool {
    let Some(tributary_validator) = self.get_tributary_validator_by_evrf_index(participant) else {
      return false;
    };

    &tributary_validator.get_serai_networks_auxiliary_key().to_bytes() == serai_auxiliary
  }

  /// Get the total weight of all validators in the set.
  pub fn total_weight(&self) -> u16 {
    self.total_weight
  }

  /// Get the threshold for the eVRF protocol, calculated as `(n * 2/3) + 1`.
  pub fn evrf_threshold(&self) -> u16 {
    self.evrf_threshold
  }

  /// All of our topics require 2/3rds participation.
  pub fn required_participation(&self) -> u16 {
    required_participation(self.total_weight())
  }

  /// Get the substrate public keys from the EVRF public keys.
  pub fn evrf_networks_substrate_keys(&self) -> &[[u8; 32]] {
    &self.evrf_networks_substrate_keys
  }

  /// Get the network public keys from the EVRF public keys.
  pub fn evrf_networks_external_keys(&self) -> &[Vec<u8>] {
    &self.evrf_networks_external_keys
  }
}
