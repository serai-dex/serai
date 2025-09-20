use sp_core::sr25519::Public;

use serai_abi::primitives::{crypto::SignedEmbeddedEllipticCurveKeys, network_id::*};

use frame_support::storage::StorageDoubleMap;

pub(crate) trait EmbeddedEllipticCurveKeysStorage {
  /// An map storing keys on an embedded elliptic curve.
  ///
  /// This is opaque and to be exclusively read/write by `EmbeddedEllipticCurveKeys`.
  type EmbeddedEllipticCurveKeys: StorageDoubleMap<
    ExternalNetworkId,
    Public,
    serai_abi::primitives::crypto::EmbeddedEllipticCurveKeys,
    Query = Option<serai_abi::primitives::crypto::EmbeddedEllipticCurveKeys>,
  >;
}

/// An interface for managing validators' embedded elliptic curve keys.
pub(crate) trait EmbeddedEllipticCurveKeys {
  /// Set a validator's embedded elliptic curve keys for an external network.
  fn set_embedded_elliptic_curve_keys(
    validator: Public,
    keys: SignedEmbeddedEllipticCurveKeys,
  ) -> Result<(), ()>;
  /// Check if a validator still needs to set embedded elliptic curve keys.
  fn still_needs_to_set_embedded_elliptic_curve_keys(network: NetworkId, validator: Public)
    -> bool;
}

impl<S: EmbeddedEllipticCurveKeysStorage> EmbeddedEllipticCurveKeys for S {
  /// Set a validator's embedded elliptic curve keys, for an external network.
  fn set_embedded_elliptic_curve_keys(
    validator: Public,
    keys: SignedEmbeddedEllipticCurveKeys,
  ) -> Result<(), ()> {
    let keys = keys.verify(validator.into()).ok_or(())?;
    S::EmbeddedEllipticCurveKeys::set(keys.network(), validator, Some(keys));
    Ok(())
  }

  /// Check if a validator still needs to set embedded elliptic curve keys.
  fn still_needs_to_set_embedded_elliptic_curve_keys(
    network: NetworkId,
    validator: Public,
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
