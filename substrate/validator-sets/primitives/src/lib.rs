#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode, MaxEncodedLen};
#[cfg(feature = "std")]
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

/// The type used for amounts.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(TypeInfo, Serialize, Deserialize))]
pub struct Amount(pub u64);

/// The type used to identify curves.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(TypeInfo, Serialize, Deserialize))]
pub struct Curve(pub u16);

/// The type used to identify coins.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(TypeInfo, Serialize, Deserialize))]
pub struct Coin(pub u32);

/// The type used to identify a specific session of validators.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(TypeInfo, Serialize, Deserialize))]
pub struct Session(pub u32);

/// The type used to identify a validator set.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(TypeInfo, Serialize, Deserialize))]
pub struct ValidatorSetIndex(pub u16);

/// The type used to identify a specific validator set during a specific session.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(TypeInfo, Serialize, Deserialize))]
pub struct ValidatorSetInstance(pub Session, pub ValidatorSetIndex);
