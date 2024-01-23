use core::ops::{Add, Sub, Mul};

#[cfg(feature = "std")]
use zeroize::Zeroize;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::{Coin, Amount};

/// The type used for balances (a Coin and Balance).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Balance {
  pub coin: Coin,
  pub amount: Amount,
}

impl Add<Amount> for Balance {
  type Output = Balance;
  fn add(self, other: Amount) -> Balance {
    Balance { coin: self.coin, amount: self.amount + other }
  }
}

impl Sub<Amount> for Balance {
  type Output = Balance;
  fn sub(self, other: Amount) -> Balance {
    Balance { coin: self.coin, amount: self.amount - other }
  }
}

impl Mul<Amount> for Balance {
  type Output = Balance;
  fn mul(self, other: Amount) -> Balance {
    Balance { coin: self.coin, amount: self.amount * other }
  }
}
