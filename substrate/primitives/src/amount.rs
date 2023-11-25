use core::{
  ops::{Add, Sub, Mul},
  fmt::Debug,
};

#[cfg(feature = "std")]
use zeroize::Zeroize;

#[cfg(feature = "std")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

/// The type used for amounts within Substrate.
// Distinct from Amount due to Substrate's requirements on this type.
// While Amount could have all the necessary traits implemented, not only are they many, it'd make
// Amount a large type with a variety of misc functions.
// The current type's minimalism sets clear bounds on usage.
pub type SubstrateAmount = u64;
/// The type used for amounts.
#[derive(
  Clone, Copy, PartialEq, Eq, PartialOrd, Debug, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize, BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Amount(pub SubstrateAmount);

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
