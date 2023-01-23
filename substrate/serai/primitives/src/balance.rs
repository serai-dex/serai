use core::ops::{Add, Sub, Mul};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use crate::{Coin, Amount};

/// The type used for balances (a Coin and Balance).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
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
