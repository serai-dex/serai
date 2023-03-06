#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

/// The type used to identify a specific session of validators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct Session(pub u32);

/// The type used to identify a validator set.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct ValidatorSetIndex(pub u16);

/// The type used to identify a specific validator set during a specific session.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize, Serialize, Deserialize))]
pub struct ValidatorSetInstance {
  pub session: Session,
  pub index: ValidatorSetIndex,
}