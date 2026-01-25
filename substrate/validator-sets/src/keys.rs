use sp_core::sr25519::Public as SchnorrkelPublic;

use serai_abi::primitives::{
  crypto::{ExternalKey, KeyPair},
  validator_sets::ExternalValidatorSet,
};

use frame_support::storage::StorageMap;

/// The storage underlying `Keys`.
pub(crate) trait KeysStorage {
  /// An map storing the keys validator sets use for oraclization.
  ///
  /// This is to be solely written to by `Keys`, but may be read by the rest of the pallet. Values
  /// for historical sessions may be pruned, per the definition in the `Sessions` abstraction.
  type OraclizationKeys: StorageMap<
    ExternalValidatorSet,
    SchnorrkelPublic,
    Query = Option<SchnorrkelPublic>,
  >;

  /// An map storing keys validator sets use for interacting with external networks.
  ///
  /// This is to be solely written to by `Keys`, but may be read by the rest of the pallet. Values
  /// for historical sessions may be pruned, per the definition in the `Sessions` abstraction.
  type ExternalKeys: StorageMap<ExternalValidatorSet, ExternalKey, Query = Option<ExternalKey>>;
}

/// An interface for managing validators' keys.
pub(crate) trait Keys {
  /// If a validator set has yet to set their keys.
  #[must_use]
  fn still_needs_to_set_keys(set: ExternalValidatorSet) -> bool;

  /// Set the pair of keys for an external network's validator set.
  fn set_keys(set: ExternalValidatorSet, key_pair: KeyPair);

  /// Prune a historical validator set's keys.
  fn prune_historical_set_regarding_keys(set: ExternalValidatorSet);
}

impl<S: KeysStorage> Keys for S {
  fn still_needs_to_set_keys(set: ExternalValidatorSet) -> bool {
    !S::OraclizationKeys::contains_key(set)
  }

  fn set_keys(set: ExternalValidatorSet, key_pair: KeyPair) {
    S::OraclizationKeys::insert(set, SchnorrkelPublic::from(key_pair.0 .0));
    S::ExternalKeys::insert(set, key_pair.1);
  }

  fn prune_historical_set_regarding_keys(set: ExternalValidatorSet) {
    S::OraclizationKeys::remove(set);
    S::ExternalKeys::remove(set);
  }
}
