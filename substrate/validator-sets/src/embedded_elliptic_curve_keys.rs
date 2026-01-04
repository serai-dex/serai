use serai_abi::primitives::{
  address::SeraiAddress,
  crypto::{
    EmbeddedEllipticCurveKeys as EmbeddedEllipticCurveKeysStruct, SignedEmbeddedEllipticCurveKeys,
  },
  network_id::*,
};

use frame_support::storage::StorageDoubleMap;

pub(crate) trait EmbeddedEllipticCurveKeysStorage {
  /// An map storing keys on an embedded elliptic curve.
  ///
  /// This is opaque and to be exclusively read/write by `EmbeddedEllipticCurveKeys`.
  type EmbeddedEllipticCurveKeys: StorageDoubleMap<
    ExternalNetworkId,
    SeraiAddress,
    EmbeddedEllipticCurveKeysStruct,
    Query = Option<EmbeddedEllipticCurveKeysStruct>,
  >;
}

/// An interface for managing validators' embedded elliptic curve keys.
pub(crate) trait EmbeddedEllipticCurveKeys {
  /// Set a validator's embedded elliptic curve keys for an external network.
  fn set_embedded_elliptic_curve_keys(
    validator: SeraiAddress,
    keys: SignedEmbeddedEllipticCurveKeys,
  ) -> Result<EmbeddedEllipticCurveKeysStruct, ()>;

  /// Get a validator's embedded elliptic curve keys, for an external network.
  fn embedded_elliptic_curve_keys(
    validator: SeraiAddress,
    network: ExternalNetworkId,
  ) -> Option<EmbeddedEllipticCurveKeysStruct>;

  /// Check if a validator still needs to set embedded elliptic curve keys.
  fn still_needs_to_set_embedded_elliptic_curve_keys(
    network: NetworkId,
    validator: SeraiAddress,
  ) -> bool;
}

impl<S: EmbeddedEllipticCurveKeysStorage> EmbeddedEllipticCurveKeys for S {
  /// Set a validator's embedded elliptic curve keys, for an external network.
  fn set_embedded_elliptic_curve_keys(
    validator: SeraiAddress,
    keys: SignedEmbeddedEllipticCurveKeys,
  ) -> Result<EmbeddedEllipticCurveKeysStruct, ()> {
    let keys = keys.verify(validator).ok_or(())?;
    S::EmbeddedEllipticCurveKeys::insert(keys.network(), validator, keys);
    Ok(keys)
  }

  /// Get a validator's embedded elliptic curve keys, for an external network.
  fn embedded_elliptic_curve_keys(
    validator: SeraiAddress,
    network: ExternalNetworkId,
  ) -> Option<EmbeddedEllipticCurveKeysStruct> {
    S::EmbeddedEllipticCurveKeys::get(network, validator)
  }

  /// Check if a validator still needs to set embedded elliptic curve keys.
  fn still_needs_to_set_embedded_elliptic_curve_keys(
    network: NetworkId,
    validator: SeraiAddress,
  ) -> bool {
    match network {
      // Validators never need to set embedded elliptic curve keys for Serai
      NetworkId::Serai => false,
      NetworkId::External(network) => {
        !S::EmbeddedEllipticCurveKeys::contains_key(network, validator)
      }
    }
  }
}
