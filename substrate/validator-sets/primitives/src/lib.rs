#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_core::{ConstU32, sr25519, bounded::BoundedVec};

use serai_primitives::{NetworkId, Network, Amount};

// Support keys up to 96 bytes (BLS12-381 G2).
const MAX_KEY_LEN: u32 = 96;

/// The type used to identify a specific session of validators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct Session(pub u32);

/// The type used to identify a specific validator set during a specific session.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct ValidatorSet {
  pub session: Session,
  pub network: NetworkId,
}

/// The data for a validator set.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct ValidatorSetData {
  pub bond: Amount,
  pub network: Network,

  // Participant and their amount bonded to this set
  // Limit each set to 100 participants for now
  pub participants: BoundedVec<(sr25519::Public, Amount), ConstU32<100>>,
}

type MaxKeyLen = ConstU32<MAX_KEY_LEN>;
/// The type representing a Key from an external network.
pub type ExternalKey = BoundedVec<u8, MaxKeyLen>;

/// A Validator Set's Ristretto key, used for signing InInstructions, and their key on the external
/// network.
pub type KeyPair = (sr25519::Public, ExternalKey);
