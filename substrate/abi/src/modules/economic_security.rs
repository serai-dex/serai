use serai_primitives::{
  network_id::ExternalNetworkId,
  balance::{Amount, ExternalBalance},
};

/// A trait representing access to the information on economic security.
pub trait EconomicSecurity {
  /// If an external network has _ever_ achieved economic security.
  #[must_use]
  fn achieved_economic_security(network: ExternalNetworkId) -> bool;

  /// The security oracle's valuation of this balance in SRI.
  ///
  /// This may return `Amount(u64::MAX)` to represent an overflow.
  fn sri_value(balance: ExternalBalance) -> Amount;
}
