use super::*;

impl<T: Config> Pallet<T> {
  pub(crate) fn account() -> T::AccountId {
    SeraiAddress::system(b"ValidatorSets")
  }

  /// The latest decided session for a network.
  pub fn latest_decided_session(network: NetworkId) -> Option<Session> {
    LatestDecidedSession::<T>::get(network)
  }

  /// The current session for a network.
  pub fn current_session(network: NetworkId) -> Option<Session> {
    CurrentSession::<T>::get(network)
  }

  /// The amount of key shares a validator set has.
  ///
  /// This will return `None` for historic set, per the definition in the `Sessions` abstraction.
  pub fn key_shares(set: ValidatorSet) -> Option<KeySharesStruct> {
    KeyShares::<T>::get(set)
  }

  /// If a validator is present within the specified validator set.
  ///
  /// This MAY return `false` for _any_ historic set, per the definition in the `Sessions`
  /// abstraction, even if the validator _was_ present.
  pub fn in_validator_set(set: ValidatorSet, validator: SeraiAddress) -> bool {
    SelectedValidators::<T>::contains_key(set, validator)
  }

  /// The key shares possessed by a validator within a specific validator set.
  ///
  /// This MAY return `None` for _any_ historic set, per the definition in the `Sessions`
  /// abstraction, even if the validator _was_ present.
  pub fn key_shares_possessed_by_validator(
    set: ValidatorSet,
    validator: SeraiAddress,
  ) -> Option<KeySharesStruct> {
    SelectedValidators::<T>::get(set, validator).map(|(_aux_key, key_shares)| key_shares)
  }

  /// The stake for the current validator set for a network.
  pub fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
    Abstractions::<T>::stake_for_current_validator_set(network)
  }

  /// The stake for the latest decided validator set for a network.
  pub fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount> {
    Abstractions::<T>::stake_for_latest_decided_validator_set(network)
  }

  /// The validators selected for a validator set.
  ///
  /// This will return an empty iterator for a set which hasn't been decided and MAY do so for
  /// _any_ historic set, per the definition in the `Sessions` abstraction.
  pub fn selected_validators(
    set: ValidatorSet,
  ) -> impl Iterator<Item = (SeraiAddress, KeySharesStruct)> {
    SelectedValidators::<T>::iter_prefix(set)
      .map(|(validator, (_aux_key, key_shares))| (validator, key_shares))
  }

  /// The oraclization key for a validator set.
  ///
  /// This will return `None` for a validator set which hasn't set their keys and MAY return `None`
  /// for _any_ historic set, per the definition in the `Sessions` abstraction.
  pub fn oraclization_key(set: ExternalValidatorSet) -> Option<SchnorrkelPublic> {
    OraclizationKeys::<T>::get(set)
  }

  /// The external key for a validator set.
  ///
  /// This will return `None` for a validator set which hasn't set their keys and MAY return `None`
  /// for _any_ historic set, per the definition in the `Sessions` abstraction.
  pub fn external_key(set: ExternalValidatorSet) -> Option<ExternalKey> {
    ExternalKeys::<T>::get(set)
  }

  /// If a validator set's slash report is still pending submission.
  pub fn pending_slash_report(set: ExternalValidatorSet) -> bool {
    Abstractions::<T>::should_still_publish_slash_report(set).is_some()
  }

  /// The auxiliary keys for a validator.
  ///
  /// These are the most recently declared keys and not the keys selected for usage within some
  /// context. This likely SHOULD NOT be used, except over the RPC to provide context on the state.
  pub fn auxiliary_keys(
    validator: SeraiAddress,
    network: NetworkId,
  ) -> Option<AuxiliaryKeysStruct> {
    AuxiliaryKeys::<T>::get(network, validator)
  }
}
