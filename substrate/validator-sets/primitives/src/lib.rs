#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::{Add, Mul};

use scale::{Encode, Decode, MaxEncodedLen};
#[cfg(feature = "std")]
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

/// The type used for amounts.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(TypeInfo, Serialize, Deserialize))]
pub struct Amount(pub u64);

impl Add<Amount> for Amount {
  type Output = Amount;
  fn add(self, other: Amount) -> Amount {
    Amount(self.0 + other.0)
  }
}

impl Mul<Amount> for Amount {
  type Output = Amount;
  fn mul(self, other: Amount) -> Amount {
    Amount(self.0 * other.0)
  }
}

/// One whole coin with eight decimals.
#[allow(clippy::inconsistent_digit_grouping)]
pub const COIN: Amount = Amount(1_000_000_00);

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
