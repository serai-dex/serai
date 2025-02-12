use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::network_id::ExternalNetworkId;

/// A signal.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub enum Signal {
  /// A signal to retire the current protocol.
  Retire {
    /// The protocol to retire in favor of.
    in_favor_of: [u8; 32],
  },
  /// A signal to halt an external network.
  Halt(ExternalNetworkId),
}
