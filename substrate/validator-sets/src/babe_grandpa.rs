use alloc::vec::Vec;

use sp_core::{
  crypto::{DeriveJunction, Derive as _},
  sr25519::Public as SchnorrkelPublic,
};

use serai_abi::primitives::{
  address::SeraiAddress, network_id::NetworkId, crypto::EmbeddedEllipticCurveKeys,
};

/// Convert a list of validators, such as from `Abstractions::<T>::selected_validators`, to a list
/// including their corresponding auxilliary key for Serai.
///
/// This will panic if `EmbeddedEllipticCurveKeys::Serai` is not set for the validator. We assume
/// as an invariant that _every_ validator has set this.
pub(super) fn validators_to_validators_with_serai_auxilliary_key<
  E: crate::EmbeddedEllipticCurveKeys,
  K,
>(
  validators: impl IntoIterator<Item = (SeraiAddress, K)>,
) -> Vec<(SeraiAddress, SchnorrkelPublic)> {
  validators
    .into_iter()
    .map(|(validator, _key_shares)| {
      let embedded_elliptic_curve_keys =
        E::embedded_elliptic_curve_keys(validator, NetworkId::Serai);
      (
        validator,
        match embedded_elliptic_curve_keys {
          Some(EmbeddedEllipticCurveKeys::Serai(ristretto)) => SchnorrkelPublic::from(ristretto),
          Some(_) => {
            panic!("requested `EmbeddedEllipticCurveKeys::Serai` and received `_`")
          }
          None => {
            panic!("selected validator lacked `EmbeddedEllipticCurveKeys::Serai`")
          }
        },
      )
    })
    .collect()
}

pub(super) fn validators_to_babe_validators(
  validators: &[(SeraiAddress, SchnorrkelPublic)],
) -> impl Iterator<Item = (&SeraiAddress, pallet_babe::AuthorityId)> {
  let mut derivation = [0; 32];
  derivation[28 ..].copy_from_slice(&sp_consensus_babe::KEY_TYPE.0);
  // This returns `None` if the iterator has a hard junction, making this `unwrap` safe
  validators.iter().map(move |(validator, validator_key)| {
    (
      validator,
      (*validator_key).derive(core::iter::once(DeriveJunction::Soft(derivation))).unwrap().into(),
    )
  })
}

pub(super) fn validators_to_grandpa_validators(
  validators: &[(SeraiAddress, SchnorrkelPublic)],
) -> impl Iterator<Item = (&SeraiAddress, pallet_grandpa::AuthorityId)> {
  let mut derivation = [0; 32];
  derivation[28 ..].copy_from_slice(&sp_consensus_grandpa::KEY_TYPE.0);
  validators.iter().map(move |(validator, validator_key)| {
    (
      validator,
      (*validator_key).derive(core::iter::once(DeriveJunction::Soft(derivation))).unwrap().into(),
    )
  })
}
