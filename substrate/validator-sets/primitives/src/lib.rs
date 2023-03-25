#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use serai_primitives::NetworkId;

/// The type used to identify a specific session of validators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct Session(pub u32);

/// The type used to identify a specific validator set during a specific session.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct ValidatorSet {
  pub session: Session,
  pub network: NetworkId,
}
