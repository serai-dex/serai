use core::ops::{Add, Sub, Mul};

#[cfg(feature = "std")]
use zeroize::Zeroize;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::{Amount, Coin, ExternalCoin};

/// The type used for balances (a Coin and Balance).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Balance {
  pub coin: Coin,
  pub amount: Amount,
}

/// The type used for balances (a Coin and Balance).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExternalBalance {
  pub coin: ExternalCoin,
  pub amount: Amount,
}

impl From<ExternalBalance> for Balance {
  fn from(balance: ExternalBalance) -> Self {
    Balance { coin: balance.coin.into(), amount: balance.amount }
  }
}

impl TryFrom<Balance> for ExternalBalance {
  type Error = ();

  fn try_from(balance: Balance) -> Result<Self, Self::Error> {
    match balance.coin {
      Coin::Serai => Err(())?,
      Coin::External(coin) => Ok(ExternalBalance { coin, amount: balance.amount }),
    }
  }
}

// TODO: these impl either should be removed or return errors in case of overflows
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
