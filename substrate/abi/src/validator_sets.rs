pub use serai_validator_sets_primitives as primitives;

use serai_primitives::*;
use serai_validator_sets_primitives::*;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Call {
  set_keys {
    network: NetworkId,
    removed_participants: Vec<SeraiAddress>,
    key_pair: KeyPair,
    signature: Signature,
  },
  allocate {
    network: NetworkId,
    amount: Amount,
  },
  deallocate {
    network: NetworkId,
    amount: Amount,
  },
  claim_deallocation {
    network: NetworkId,
    session: Session,
  },
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Event {
  NewSet {
    set: ValidatorSet,
  },
  ParticipantRemoved {
    set: ValidatorSet,
    removed: SeraiAddress,
  },
  KeyGen {
    set: ValidatorSet,
    key_pair: KeyPair,
  },
  AllocationIncreased {
    validator: SeraiAddress,
    network: NetworkId,
    amount: Amount,
  },
  AllocationDecreased {
    validator: SeraiAddress,
    network: NetworkId,
    amount: Amount,
    delayed_until: Option<Session>,
  },
  DeallocationClaimed {
    validator: SeraiAddress,
    network: NetworkId,
    session: Session,
  },
  SetRetired {
    set: ValidatorSet,
  },
}
