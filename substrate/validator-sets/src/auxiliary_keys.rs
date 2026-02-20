use serai_abi::{
  primitives::{
    address::SeraiAddress,
    crypto::{
      EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct,
      SignedEmbeddedEllipticCurveKeys as SignedAuxiliaryKeys,
    },
    network_id::*,
  },
  validator_sets::Event,
};

use frame_support::storage::StorageDoubleMap;

pub(crate) trait EmitEvent {
  fn emit(event: Event);
}
impl<T: serai_core_pallet::Config> EmitEvent for serai_core_pallet::Pallet<T> {
  fn emit(event: Event) {
    Self::emit_event(event);
  }
}
#[cfg(test)]
impl EmitEvent for () {
  fn emit(_event: Event) {}
}

/// The storage underlying `AuxiliaryKeys`.
pub(crate) trait AuxiliaryKeysStorage {
  type EmitEvent: EmitEvent;

  /// An map storing auxiliary keys.
  ///
  /// The network of the values are guaranteed to correspond to the network they're keyed
  /// by.
  ///
  /// This is to be solely written to by `AuxiliaryKeys`, but may be read by the rest of the
  /// pallet. It likely SHOULD NOT be read by the rest of the pallet though, as it represents the
  /// auxiliary keys most recently declared by the validator, not the auxiliary keys in use for the
  /// validator within current contexts.
  type AuxiliaryKeys: StorageDoubleMap<
    NetworkId,
    SeraiAddress,
    AuxiliaryKeysStruct,
    Query = Option<AuxiliaryKeysStruct>,
  >;
}

/// An interface for managing validators' auxiliary keys.
pub(crate) trait AuxiliaryKeys {
  /// Set a validator's auxiliary keys.
  ///
  /// This will emit the expected event defined within [`serai-abi`].
  ///
  /// This will return an error if and only if the keys weren't valid.
  ///
  /// This function will be atomic, only modifying the storage if it will return `Ok(())`.
  fn set_auxiliary_keys(
    validator: SeraiAddress,
    keys: SignedAuxiliaryKeys,
  ) -> Result<AuxiliaryKeysStruct, ()>;

  /// Check if a validator set the necessary auxiliary keys to validate for this network.
  ///
  /// This does not yield _which_ auxiliary keys need to be set to validate for this network, if
  /// any are missing. At the time of writing this docstring, the validator must set axuliary keys
  /// for all networks in `[NetworkId::Serai, network].into_iter().collect::<HashSet<_>>()`.
  fn has_necessary_auxiliary_keys(validator: SeraiAddress, network: NetworkId) -> bool;
}

impl<S: AuxiliaryKeysStorage> AuxiliaryKeys for S {
  fn set_auxiliary_keys(
    validator: SeraiAddress,
    keys: SignedAuxiliaryKeys,
  ) -> Result<AuxiliaryKeysStruct, ()> {
    let keys = keys.verify(validator).ok_or(())?;
    S::AuxiliaryKeys::insert(keys.network(), validator, keys);
    S::EmitEvent::emit(Event::SetEmbeddedEllipticCurveKeys { validator, keys });
    Ok(keys)
  }

  fn has_necessary_auxiliary_keys(validator: SeraiAddress, network: NetworkId) -> bool {
    // A validator must always declare an identity to operate their validator with
    let set_serai = S::AuxiliaryKeys::contains_key(NetworkId::Serai, validator);
    // The validator must also declare their auxiliary keys for _this_ specific network
    let set_network = match network {
      NetworkId::Serai => set_serai,
      NetworkId::External(network) => S::AuxiliaryKeys::contains_key(network, validator),
    };
    set_serai && set_network
  }
}

#[cfg(test)]
mod mock {
  use frame_support::{pallet_prelude::*, traits::StorageInstance};
  use serai_abi::primitives::{
    network_id::NetworkId, crypto::EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct,
    address::SeraiAddress,
  };

  pub struct Keys;
  impl StorageInstance for Keys {
    fn pallet_prefix() -> &'static str {
      "Allocations"
    }
    const STORAGE_PREFIX: &'static str = "Storage::AuxiliaryKeys";
  }
  type AuxiliaryKeysMap = StorageDoubleMap<
    Keys,
    Identity,
    NetworkId,
    Blake2_128Concat,
    SeraiAddress,
    AuxiliaryKeysStruct,
    OptionQuery,
  >;
  impl super::AuxiliaryKeysStorage for crate::MockStorage {
    type EmitEvent = ();

    type AuxiliaryKeys = AuxiliaryKeysMap;
  }
}
