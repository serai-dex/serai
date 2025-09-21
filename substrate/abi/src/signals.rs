use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  address::SeraiAddress,
  network_id::{ExternalNetworkId, NetworkId},
  signals::Signal,
};

/// A call to signals.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Call {
  /// Register a retirement signal.
  register_retirement_signal {
    /// The protocol favored over the current protocol.
    in_favor_of: [u8; 32],
  },
  /// Revoke a retirement signal.
  revoke_retirement_signal {
    /// The protocol which was favored over the current protocol
    was_in_favor_of: [u8; 32],
  },
  /// Favor a signal.
  favor {
    /// The signal to favor.
    signal: Signal,
    /// The network this validator is expressing favor with.
    ///
    /// A validator may be an active validator for multiple networks. The validator must specify
    /// which network they're expressing favor with in this call.
    with_network: NetworkId,
  },
  /// Revoke favor for a signal.
  revoke_favor {
    /// The signal to revoke favor for.
    signal: Signal,
    /// The network this validator is revoking favor with.
    ///
    /// A validator may have expressed favor with multiple networks. The validator must specify
    /// which network they're revoking favor with in this call.
    with_network: NetworkId,
  },
  /// Stand against a signal.
  ///
  /// This has no effects other than emitting an event that this signal is stood against. If the
  /// origin has prior expressed favor, they must still call `revoke_favor` for each network they
  /// expressed favor with.
  stand_against {
    /// The signal to stand against.
    signal: Signal,
    /// The network this validator is standing against the signal on behalf of.
    with_network: NetworkId,
  },
}

impl Call {
  pub(crate) fn is_signed(&self) -> bool {
    match self {
      Call::register_retirement_signal { .. } |
      Call::revoke_retirement_signal { .. } |
      Call::favor { .. } |
      Call::revoke_favor { .. } |
      Call::stand_against { .. } => true,
    }
  }
}

/// An event from signals.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// A retirement signal has been registered.
  RetirementSignalRegistered {
    /// The retirement signal's ID.
    signal: [u8; 32],
    /// The protocol retirement is proposed in favor of.
    in_favor_of: [u8; 32],
    /// The address which registered this signal.
    registrant: SeraiAddress,
  },
  /// A retirement signal was revoked.
  RetirementSignalRevoked {
    /// The retirement signal's ID.
    signal: [u8; 32],
  },
  /// A signal was favored.
  SignalFavored {
    /// The signal favored.
    signal: Signal,
    /// The validator the signal was favored by.
    by: SeraiAddress,
    /// The network with which the signal was favored.
    with_network: NetworkId,
  },
  /// Favor for a signal was revoked.
  FavorRevoked {
    /// The signal whose favor was revoked.
    signal: Signal,
    /// The validator who revoked their favor for the signal.
    by: SeraiAddress,
    /// The network with which favor for the signal was revoked.
    with_network: NetworkId,
  },
  /// A supermajority of a network's validator set now favor a signal.
  NetworkInFavor {
    /// The signal which now has a supermajority of a network's validator set favoring it.
    signal: Signal,
    /// The network which is now considered to favor the signal.
    network: NetworkId,
  },
  /// A network's validator set is no longer considered to favor a signal.
  NetworkNoLongerInFavor {
    /// The signal which no longer has the network considered in favor of it.
    signal: Signal,
    /// The network which is no longer considered to be in favor of the signal.
    network: NetworkId,
  },
  /// A retirement signal has been locked in.
  RetirementSignalLockedIn {
    /// The signal which has been locked in.
    signal: [u8; 32],
  },
  /// A network's ability to publish batches was halted.
  ///
  /// This also halts set rotation in effect, as handovers are via new sets starting to publish
  /// batches.
  NetworkHalted {
    /// The network which has been halted.
    network: ExternalNetworkId,
  },
  /// An account has stood against a signal.
  AgainstSignal {
    /// The signal stood against.
    signal: Signal,
    /// The account which stood against the signal.
    account: SeraiAddress,
    /// The network with which this was expressed.
    with_network: NetworkId,
  },
}
