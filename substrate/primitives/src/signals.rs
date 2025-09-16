use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::{network_id::ExternalNetworkId, address::SeraiAddress};

/// The ID of an protocol.
pub type ProtocolId = [u8; 32];

/// A signal.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  allow(clippy::cast_possible_truncation),
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen)
)]
pub enum Signal {
  /// A signal to retire the current protocol.
  Retire {
    /// The protocol to retire in favor of.
    in_favor_of: ProtocolId,
  },
  /// A signal to halt an external network.
  Halt(ExternalNetworkId),
}

/// A retirement signal, registered on chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen)
)]
pub struct RegisteredRetirementSignal {
  /// The protocol to retire in favor of.
  pub in_favor_of: ProtocolId,
  /// The registrant of this signal.
  pub registrant: SeraiAddress,
  /// The block number this was registered at.
  pub registered_at: u64,
}

impl RegisteredRetirementSignal {
  /// The ID of this signal.
  pub fn id(&self) -> ProtocolId {
    sp_core::blake2_256(&borsh::to_vec(self).unwrap())
  }
}
