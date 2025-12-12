use alloc::vec::Vec;
use serai_abi::primitives::{
  crypto::{Public, EmbeddedEllipticCurveKeys, SignedEmbeddedEllipticCurveKeys, KeyPair},
  network_id::{ExternalNetworkId, NetworkId},
  validator_sets::{Session, ExternalValidatorSet},
  balance::{Amount, Balance},
  address::SeraiAddress,
};

/// The genesis configuration for Serai.
#[derive(scale::Encode, scale::Decode)]
pub struct GenesisConfig {
  /// The genesis validators for the network.
  pub validators: Vec<(Public, Vec<SignedEmbeddedEllipticCurveKeys>)>,
  /// The accounts to start with balances, intended solely for testing purposes.
  pub coins: Vec<(Public, Balance)>,
}

sp_api::decl_runtime_apis! {
  pub trait GenesisApi {
    fn build(genesis: GenesisConfig);
  }
  pub trait SeraiApi {
    fn events() -> Vec<Vec<Vec<u8>>>;
    fn validators(network: NetworkId) -> Vec<Public>;
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
