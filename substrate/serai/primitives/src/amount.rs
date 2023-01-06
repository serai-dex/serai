use core::{ops::{Add, Mul}};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

/// The type used for amounts.
#[derive(
  Clone, Copy, PartialEq, Eq, PartialOrd, Debug, Encode, Decode, TypeInfo, MaxEncodedLen,
)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Amount(pub u64);

/// One whole coin with eight decimals.
#[allow(clippy::inconsistent_digit_grouping)]
pub const COIN: Amount = Amount(1_000_000_00);

impl Add for Amount {
  type Output = Amount;
  fn add(self, other: Amount) -> Amount {
    Amount(self.0 + other.0)
  }
}

impl Mul for Amount {
  type Output = Amount;
  fn mul(self, other: Amount) -> Amount {
    Amount(self.0 * other.0)
  }
}
