use sp_core::sr25519::Public as SchnorrkelPublic;

use serai_abi::primitives::{
  crypto::{ExternalKey, KeyPair},
  validator_sets::ExternalValidatorSet,
};

use frame_support::storage::StorageMap;

/// The storage underlying `Keys`.
pub(crate) trait KeysStorage {
  /// A map storing the keys validator sets use for oraclization.
  ///
  /// This is to be solely written to by `Keys`, but may be read by the rest of the pallet. Values
  /// for historical sessions may be pruned, per the definition in the `Sessions` abstraction.
  type OraclizationKeys: StorageMap<
    ExternalValidatorSet,
    SchnorrkelPublic,
    Query = Option<SchnorrkelPublic>,
  >;

  /// A map storing keys validator sets use for interacting with external networks.
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

#[cfg(test)]
mod mock {
  use serai_abi::primitives::{validator_sets::ExternalValidatorSet, crypto::ExternalKey};

  use sp_core::sr25519::Public as SchnorrkelPublic;
  use frame_support::{
    pallet_prelude::*,
    traits::StorageInstance,
    storage::types::{StorageMap, OptionQuery},
  };

  pub struct OraclizationStorage;
  impl StorageInstance for OraclizationStorage {
    fn pallet_prefix() -> &'static str {
      "ValidatorSets"
    }
    const STORAGE_PREFIX: &'static str = "Storage::OraclizationKeys";
  }
  type OraclizationKeys =
    StorageMap<OraclizationStorage, Identity, ExternalValidatorSet, SchnorrkelPublic, OptionQuery>;

  pub struct ExternalStorage;
  impl StorageInstance for ExternalStorage {
    fn pallet_prefix() -> &'static str {
      "ValidatorSets"
    }
    const STORAGE_PREFIX: &'static str = "Storage::ExternalKeys";
  }
  type ExternalKeys =
    StorageMap<ExternalStorage, Identity, ExternalValidatorSet, ExternalKey, OptionQuery>;

  impl super::KeysStorage for crate::MockStorage {
    type OraclizationKeys = OraclizationKeys;
    type ExternalKeys = ExternalKeys;
  }
}

#[test]
fn test_keys_storage() {
  use sp_io::TestExternalities;
  use crate::MockStorage;

  use rand_core::{RngCore as _, OsRng};

  use serai_abi::primitives::{
    network_id::ExternalNetworkId,
    validator_sets::Session,
    crypto::{Public, KeyPair},
  };

  let rand_key_pair = || {
    let mut public = [0; 32];
    let mut external = [0; 64];

    OsRng.fill_bytes(&mut public);
    OsRng.fill_bytes(&mut external);

    KeyPair(Public(public), ExternalKey(external.to_vec().try_into().unwrap()))
  };

  TestExternalities::default().execute_with(|| {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Monero, session: Session(1) };

    // should return true before we set the keys
    assert!(MockStorage::still_needs_to_set_keys(set));

    // set the keys
    let pair = rand_key_pair();
    MockStorage::set_keys(set, pair);

    // should return false after we set the keys
    assert!(!MockStorage::still_needs_to_set_keys(set));

    // prune the set from keys
    MockStorage::prune_historical_set_regarding_keys(set);

    // they should not exist in the storage now
    assert!(!<MockStorage as KeysStorage>::ExternalKeys::contains_key(set));
    assert!(!<MockStorage as KeysStorage>::OraclizationKeys::contains_key(set));
  });
}
