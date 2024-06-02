use serai_primitives::{NetworkId, SeraiAddress};

use serai_validator_sets_primitives::ValidatorSet;

pub use serai_signals_primitives as primitives;
use primitives::SignalId;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Call {
  register_retirement_signal { in_favor_of: [u8; 32] },
  revoke_retirement_signal { retirement_signal_id: [u8; 32] },
  favor { signal_id: SignalId, for_network: NetworkId },
  revoke_favor { signal_id: SignalId, for_network: NetworkId },
  stand_against { signal_id: SignalId, for_network: NetworkId },
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Event {
  RetirementSignalRegistered {
    signal_id: [u8; 32],
    in_favor_of: [u8; 32],
    registrant: SeraiAddress,
  },
  RetirementSignalRevoked {
    signal_id: [u8; 32],
  },
  SignalFavored {
    signal_id: SignalId,
    by: SeraiAddress,
    for_network: NetworkId,
  },
  SetInFavor {
    signal_id: SignalId,
    set: ValidatorSet,
  },
  RetirementSignalLockedIn {
    signal_id: [u8; 32],
  },
  SetNoLongerInFavor {
    signal_id: SignalId,
    set: ValidatorSet,
  },
  FavorRevoked {
    signal_id: SignalId,
    by: SeraiAddress,
    for_network: NetworkId,
  },
  AgainstSignal {
    signal_id: SignalId,
    who: SeraiAddress,
    for_network: NetworkId,
  },
}
