use alloc::vec::Vec;
use serai_abi::primitives::{
  crypto::{EmbeddedEllipticCurveKeys, SignedEmbeddedEllipticCurveKeys, KeyPair},
  network_id::{ExternalNetworkId, NetworkId},
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
  pub trait GenesisApi {
    fn build(genesis: GenesisConfig);
  }
  pub trait SeraiApi {
    fn events() -> Vec<Vec<Vec<u8>>>;
    fn validators(network: NetworkId) -> Vec<SeraiAddress>;
    fn current_session(network: NetworkId) -> Option<Session>;
    fn current_stake(network: NetworkId) -> Option<Amount>;
    fn keys(set: ExternalValidatorSet) -> Option<KeyPair>;
    fn current_validators(network: NetworkId) -> Option<Vec<SeraiAddress>>;
    fn pending_slash_report(network: ExternalNetworkId) -> bool;
    fn embedded_elliptic_curve_keys(
      validator: SeraiAddress,
      network: ExternalNetworkId,
    ) -> Option<EmbeddedEllipticCurveKeys>;
  }
}
