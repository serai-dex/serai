use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::network_id::ExternalNetworkId;

/// An event from economic security.
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
  /// If am external network has _ever_ achieved economic security.
  #[must_use]
  fn achieved_economic_security(network: ExternalNetworkId) -> bool;
}
