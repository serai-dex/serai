use sp_core::sr25519::Public as SchnorrkelPublic;

use serai_abi::primitives::{
  crypto::{ExternalKey, KeyPair},
  validator_sets::ExternalValidatorSet,
};

use frame_support::storage::StorageMap;

pub(crate) trait KeysStorage {
  /// An map storing keys validator sets use for oraclization.
  ///
  /// This is opaque and to be exclusively read/write by `Keys`.
  type OraclizationKeys: StorageMap<
    ExternalValidatorSet,
    SchnorrkelPublic,
    Query = Option<SchnorrkelPublic>,
  >;

  /// An map storing keys validator sets use for interacting with external networks.
  ///
  /// This is opaque and to be exclusively read/write by `Keys`.
  type ExternalKeys: StorageMap<ExternalValidatorSet, ExternalKey, Query = Option<ExternalKey>>;
}

/// An interface for managing validators' embedded elliptic curve keys.
pub(crate) trait Keys {
  /// If a validator set has yet to set keys.
  #[must_use]
  fn needs_to_set_keys(set: ExternalValidatorSet) -> bool;

  /// Set the pair of keys for an external network.
  fn set_keys(set: ExternalValidatorSet, key_pair: KeyPair);

  /// Clear a historic set of keys.
  fn clear_keys(set: ExternalValidatorSet);

  /// The oraclization key for a validator set.
  fn oraclization_key(set: ExternalValidatorSet) -> Option<SchnorrkelPublic>;

  /// The external key for a validator set.
  fn external_key(set: ExternalValidatorSet) -> Option<ExternalKey>;
}

impl<S: KeysStorage> Keys for S {
  fn needs_to_set_keys(set: ExternalValidatorSet) -> bool {
    S::OraclizationKeys::contains_key(set)
  }

  fn set_keys(set: ExternalValidatorSet, key_pair: KeyPair) {
    S::OraclizationKeys::insert(set, SchnorrkelPublic::from(key_pair.0 .0));
    S::ExternalKeys::insert(set, key_pair.1);
  }

  fn clear_keys(set: ExternalValidatorSet) {
    S::OraclizationKeys::remove(set);
    S::ExternalKeys::remove(set);
  }

  fn oraclization_key(set: ExternalValidatorSet) -> Option<SchnorrkelPublic> {
    S::OraclizationKeys::get(set)
  }

  fn external_key(set: ExternalValidatorSet) -> Option<ExternalKey> {
    S::ExternalKeys::get(set)
  }
}
