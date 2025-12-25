use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  network_id::ExternalNetworkId,
  balance::{Amount, ExternalBalance},
};

/// An event from the economic security module.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// Economic security was achieved for a network's validator set.
  EconomicSecurityAchieved {
    /// The network whose validator set achieved economic security.
    network: ExternalNetworkId,
  },
}

/// A trait representing access to the information on economic security.
pub trait EconomicSecurity {
  /// If an external network has _ever_ achieved economic security.
  #[must_use]
  fn achieved_economic_security(network: ExternalNetworkId) -> bool;

  /// The security oracle's valuation of this balance in SRI.
  fn sri_value(balance: ExternalBalance) -> Amount;
}
