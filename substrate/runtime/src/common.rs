use alloc::vec::Vec;
use serai_abi::primitives::{
  crypto::{EmbeddedEllipticCurveKeys, SignedEmbeddedEllipticCurveKeys, KeyPair},
  network_id::NetworkId,
  validator_sets::{Session, ExternalValidatorSet},
  coin::ExternalCoin,
  balance::{Amount, Balance},
  address::SeraiAddress,
};

/// The genesis configuration for Serai.
#[derive(scale::Encode, scale::Decode)]
pub struct GenesisConfig {
  /// The genesis validators for the network.
  pub validators: Vec<(SeraiAddress, Vec<SignedEmbeddedEllipticCurveKeys>)>,
  /// The fees to use for the liquidity pools.
  ///
  /// For more information, please read the documentation of [`serai_dex_pallet::GenesisConfig`].
  pub fees: Vec<(ExternalCoin, u8)>,
  /// The accounts to start with balances, intended solely for testing purposes.
  pub coins: Vec<(SeraiAddress, Balance)>,
}

sp_api::decl_runtime_apis! {
  /// Serai's genesis API.
  ///
  /// This corresponds to [`sp_genesis_builder::GenesisBuilder`]. This exists as Substrate's
  /// methodology to effect the genesis is designed around and effectively mandates the usage of a
  /// JSON-serialized configuration. As we have the static type information, we have absolutely no
  /// reason to _want_ to use JSON.
  pub trait GenesisApi {
    /// Build the genesis block from the genesis configuration.
    fn build(genesis: GenesisConfig);
  }

  /// A monolithic API to access all desired state from the Serai protocol.
  pub trait SeraiApi {
    /// The events from the Serai protocol.
    ///
    /// This innermost `Vec<u8>` corresponds to the `borsh`-encoded `Vec`. The next `Vec`
    /// corresponds to a transaction, the list of all events which occurred during its execution.
    /// The final `Vec` corresponds to the block, the list of all transactions' lists of all
    /// events.
    fn events() -> Vec<Vec<Vec<u8>>>;
    /// The validators to use when peering.
    fn validators_for_peering(network: NetworkId) -> Vec<SeraiAddress>;
    /// The current session for the network.
    fn current_session(network: NetworkId) -> Option<Session>;
    /// The current stake for a network's current validator set.
    fn current_stake(network: NetworkId) -> Option<Amount>;
    /// The key pair for an external validator set.
    ///
    /// This fetches the value from storage which may have been pruned if the set is historical.
    fn keys(set: ExternalValidatorSet) -> Option<KeyPair>;
    /// The validators for a network's current validator set.
    fn current_validators(network: NetworkId) -> Option<Vec<SeraiAddress>>;
    /// If this validator set has a pending (should still publish) slash report.
    fn pending_slash_report(set: ExternalValidatorSet) -> bool;
    /// The most recently set embedded elliptic curve keys for the specified validator, network.
    fn embedded_elliptic_curve_keys(
      validator: SeraiAddress,
      network: NetworkId,
    ) -> Option<EmbeddedEllipticCurveKeys>;
  }
}
