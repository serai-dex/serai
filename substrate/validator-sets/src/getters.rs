use super::*;

impl<T: Config> Pallet<T> {
  /// The latest decided session for a network.
  pub fn latest_decided_session(network: NetworkId) -> Option<Session> {
    LatestDecidedSession::<T>::get(network)
  }

  /// The current session for a network.
  pub fn current_session(network: NetworkId) -> Option<Session> {
    CurrentSession::<T>::get(network)
  }

  /// The allocation required per key share.
  pub fn allocation_per_key_share(network: NetworkId) -> Option<Amount> {
    AllocationPerKeyShare::<T>::get(network)
  }

  /// The amount of key shares a validator set has.
  ///
  /// This will return `None` for historic sets, per the definition in the `Sessions` abstraction.
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

  /// The total amount of stake allocated for this network.
  ///
  /// This function generally SHOULD NOT be used. The actual amount of stake which will be present
  /// within a validator set may, and probably will be, notably less than this value, and this
  /// value may have deallocations occur _before_ the next validator set is decided.
  pub fn total_allocated_stake_for_network(network: NetworkId) -> Amount {
    SumAllocations::<T>::get(network)
  }

  /// The amount of stake considered allocated for a network's current validator set.
  pub fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
    CurrentAllocatedStake::<T>::get(network)
  }

  /// The amount of stake considered allocated for a network's latest decided validator set.
  pub fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount> {
    LatestDecidedAllocatedStake::<T>::get(network)
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

  /// The validators selected for a validator set and their auxiliary keys for Serai.
  ///
  /// This will return an empty iterator for a set which hasn't been decided and MAY do so for
  /// _any_ historic set, per the definition in the `Sessions` abstraction.
  pub fn selected_validators_with_serai_auxiliary_keys(
    set: ValidatorSet,
  ) -> impl Iterator<Item = (SeraiAddress, SchnorrkelPublic)> {
    SelectedValidators::<T>::iter_prefix(set)
      .map(|(validator, (aux_key, _key_shares))| (validator, aux_key))
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
