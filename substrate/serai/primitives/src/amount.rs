use core::ops::{Add, Sub, Mul};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

/// The type used for amounts.
#[derive(
  Clone, Copy, PartialEq, Eq, PartialOrd, Debug, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Amount(pub u64);

impl Add for Amount {
  type Output = Amount;
  fn add(self, other: Amount) -> Amount {
    // Explicitly use checked_add so even if range checks are disabled, this is still checked
    Amount(self.0.checked_add(other.0).unwrap())
  }
}

impl Sub for Amount {
  type Output = Amount;
  fn sub(self, other: Amount) -> Amount {
    Amount(self.0.checked_sub(other.0).unwrap())
  }
}

impl Mul for Amount {
  type Output = Amount;
  fn mul(self, other: Amount) -> Amount {
    Amount(self.0.checked_mul(other.0).unwrap())
  }
}
