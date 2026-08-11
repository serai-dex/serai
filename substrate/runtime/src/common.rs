use alloc::vec::Vec;
use serai_abi::primitives::{
  crypto::{EmbeddedEllipticCurveKeys, SignedEmbeddedEllipticCurveKeys, KeyPair},
  network_id::NetworkId,
  validator_sets::{Session, ExternalValidatorSet},
  coin::{ExternalCoin, Coin},
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
    /// The (derived) IDs for validators to use when peering.
    fn validators_for_peering(network: NetworkId) -> Vec<sp_authority_discovery::AuthorityId>;
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

    /// Coin balance of a given serai account.
    fn balance(of: SeraiAddress, coin: Coin) -> Amount;
    /// Liquidity tokens balance of a given serai account for a given coin.
    fn liquidity_balance(of: SeraiAddress, coin: ExternalCoin) -> Amount;
    /// Genesis liquidity coin balance of a given serai account.
    fn genesis_liquidity_balance(of: SeraiAddress, coin: ExternalCoin) -> Amount;

    /// Supply of a coin,
    fn supply(coin: Coin) -> Amount;
    /// Liquidity supply of a coin.
    fn liquidity_supply(coin: ExternalCoin) -> Amount;
    /// Genesis liquidity supply of a coin.
    fn genesis_liquidity_supply(coin: ExternalCoin) -> Amount;

    /// Returns `true` if genesis period is completed, `false` otherwise.
    fn genesis_completed() -> bool;

    /// Next nonce to be used for this account.
    fn account_nonce(of: SeraiAddress) -> u32;

    /// Returns the time economic security was achieved, represented in milliseconds since the epoch.
    /// Returns `0` if it isn't achieved yet.
    fn economic_security_time() -> u64;
  }
}
