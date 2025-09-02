use sp_core::{Encode, sr25519::Public};

use serai_primitives::{crypto::SignedEmbeddedEllipticCurveKeys, network_id::*};

use frame_support::storage::StorageDoubleMap;

pub(crate) trait EmbeddedEllipticCurveKeysStorage {
  /// An opaque map storing keys on an embedded elliptic curve.
  type EmbeddedEllipticCurveKeys: StorageDoubleMap<
    ExternalNetworkId,
    Public,
    serai_primitives::crypto::EmbeddedEllipticCurveKeys,
    Query = Option<serai_primitives::crypto::EmbeddedEllipticCurveKeys>,
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
      NetworkId::Serai => return false,
      NetworkId::External(network) => {
        !S::EmbeddedEllipticCurveKeys::contains_key(network, validator)
      }
    }
  }
}
