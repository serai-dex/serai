use sp_application_crypto::KeyTypeId;
use sp_core::crypto::{DeriveJunction, Derive as _};

use crate::*;

/// Derive a subkey for a validator.
pub fn subkey(public: &SchnorrkelPublic, key_type: KeyTypeId) -> SchnorrkelPublic {
  let key_type: [u8; 4] = key_type.0;
  let mut derivation = [0; 32];
  derivation[28 ..].copy_from_slice(&key_type);

  /*
    This is safe as `Derive::derive` is documented to return `None` when a hard junction (requiring
    a private key) is used with a public key (without a private key). We explicitly use a soft
    junction, as possible with solely the public key.

    https://docs.rs/sp-core/39.0.0/sp_core/crypto/trait.Derive.html#method.derive
  */
  public.derive(core::iter::once(DeriveJunction::Soft(derivation))).unwrap()
}

pub(super) fn validators_to_babe_validators<KeyShares>(
  validators: &[(SeraiAddress, (SchnorrkelPublic, KeyShares))],
) -> impl Iterator<Item = (&SeraiAddress, pallet_babe::AuthorityId)> {
  validators.iter().map(move |(validator, (validator_key, _key_shares))| {
    (validator, subkey(validator_key, sp_consensus_babe::KEY_TYPE).into())
  })
}

pub(super) fn validators_to_grandpa_validators<KeyShares>(
  validators: &[(SeraiAddress, (SchnorrkelPublic, KeyShares))],
) -> impl Iterator<Item = (&SeraiAddress, pallet_grandpa::AuthorityId)> {
  validators.iter().map(move |(validator, (validator_key, _key_shares))| {
    (validator, subkey(validator_key, sp_consensus_grandpa::KEY_TYPE).into())
  })
}

impl<T: Config> Pallet<T> {
  /// Create a new (non-genesis) session for the Serai network.
  ///
  /// This is explicitly for non-genesis sessions as the two have different code paths.
  /// BABE/GRANDPA have `on_genesis_session` whereas this calls `on_new_session`. Additionally,
  /// this tailors for how there was a prior session and how it must fetch information about it/can
  /// assume that there are already validators decided and queued for the session now beginning.
  pub(crate) fn new_non_genesis_serai_session() {
    /*
      We query the validators for the current session now, as:
      1) They'll be needed later.
      2) If we do it now, they aren't historical, so we know for certain they'll be populated.
         While the definition of historical is well-documented, and would include the immediately
         prior session, not having to consider it is pleasant.
    */
    let current_serai_session_at_start = Self::current_session(NetworkId::Serai)
      .expect("`new_non_genesis_serai_session` called at genesis");
    let current_serai_validators_at_start = SelectedValidators::<T>::iter_prefix(ValidatorSet {
      network: NetworkId::Serai,
      session: current_serai_session_at_start,
    })
    .collect::<Vec<_>>();

    Babe::<T>::on_before_session_ending();
    Grandpa::<T>::on_before_session_ending();

    // As we have already decided and queued validators, accept the handover on their behalf
    Abstractions::<T>::accept_handover(NetworkId::Serai);
    // Decide the next session for the Serai network, so we may queue the selected validators
    assert!(
      Abstractions::<T>::attempt_new_session(
        NetworkId::Serai,
        include_genesis_validators::<T, T::EconomicSecurity>(NetworkId::Serai)
      ),
      "failed to attempt the next session for the Serai network"
    );

    // Update BABE, GRANDPA
    {
      let current_serai_session = Session(current_serai_session_at_start.0 + 1);
      let latest_decided_serai_session = Session(current_serai_session.0 + 1);

      debug_assert_eq!(
        Some(current_serai_session),
        Self::current_session(NetworkId::Serai),
        "current session for Serai isn't as expected"
      );
      debug_assert_eq!(
        Some(latest_decided_serai_session),
        Self::latest_decided_session(NetworkId::Serai),
        "latest decided session for Serai isn't as expected"
      );

      let serai_validators = SelectedValidators::<T>::iter_prefix(ValidatorSet {
        network: NetworkId::Serai,
        session: current_serai_session,
      })
      .collect::<Vec<_>>();

      // This is comprehensive to the validator identities, auxiliary keys, and key shares
      let validators_changed = current_serai_validators_at_start != serai_validators;

      let queued_serai_validators = SelectedValidators::<T>::iter_prefix(ValidatorSet {
        network: NetworkId::Serai,
        session: latest_decided_serai_session,
      })
      .collect::<Vec<_>>();

      Babe::<T>::on_new_session(
        validators_changed,
        validators_to_babe_validators(&serai_validators),
        validators_to_babe_validators(&queued_serai_validators),
      );
      Grandpa::<T>::on_new_session(
        validators_changed,
        validators_to_grandpa_validators(&serai_validators),
        validators_to_grandpa_validators(&queued_serai_validators),
      );

      // If any of these validators were already disabled, immediately report as such
      for i in <Self as frame_support::traits::DisabledValidators>::disabled_validators() {
        crate::Babe::<T>::on_disabled(i);
        crate::Grandpa::<T>::on_disabled(i);
      }
    }
  }
}
