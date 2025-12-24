use core::ops::{Add, Sub, Mul};
use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::coin::{ExternalCoin, Coin};

/// The type internally used to represent amounts.
// https://github.com/rust-lang/rust/issues/8995
pub type AmountRepr = u64;

/// A wrapper used to represent amounts.
#[rustfmt::skip] // Prevent rustfmt from expanding the following derive into a 10-line monstrosity
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
#[derive(Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct Amount(pub AmountRepr);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(Amount);

impl Add for Amount {
  type Output = Option<Amount>;
  fn add(self, other: Amount) -> Option<Amount> {
    self.0.checked_add(other.0).map(Amount)
  }
}

impl Sub for Amount {
  type Output = Option<Amount>;
  fn sub(self, other: Amount) -> Option<Amount> {
    self.0.checked_sub(other.0).map(Amount)
  }
}

impl Mul for Amount {
  type Output = Option<Amount>;
  fn mul(self, other: Amount) -> Option<Amount> {
    self.0.checked_mul(other.0).map(Amount)
  }
}

/// An ExternalCoin and an Amount, forming a balance for an external coin.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct ExternalBalance {
  /// The coin this is a balance for.
  pub coin: ExternalCoin,
  /// The amount of this balance.
  pub amount: Amount,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(ExternalBalance);

impl Add<Amount> for ExternalBalance {
  type Output = Option<ExternalBalance>;
  fn add(self, other: Amount) -> Option<ExternalBalance> {
    (self.amount + other).map(|amount| ExternalBalance { coin: self.coin, amount })
  }
}

impl Sub<Amount> for ExternalBalance {
  type Output = Option<ExternalBalance>;
  fn sub(self, other: Amount) -> Option<ExternalBalance> {
    (self.amount - other).map(|amount| ExternalBalance { coin: self.coin, amount })
  }
}

impl Mul<Amount> for ExternalBalance {
  type Output = Option<ExternalBalance>;
  fn mul(self, other: Amount) -> Option<ExternalBalance> {
    (self.amount * other).map(|amount| ExternalBalance { coin: self.coin, amount })
  }
}

/// A Coin and an Amount, forming a balance for a coin.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct Balance {
  /// The coin this is a balance for.
  pub coin: Coin,
  /// The amount of this balance.
  pub amount: Amount,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(Balance);

impl Add<Amount> for Balance {
  type Output = Option<Balance>;
  fn add(self, other: Amount) -> Option<Balance> {
    (self.amount + other).map(|amount| Balance { coin: self.coin, amount })
  }
}

impl Sub<Amount> for Balance {
  type Output = Option<Balance>;
  fn sub(self, other: Amount) -> Option<Balance> {
    (self.amount - other).map(|amount| Balance { coin: self.coin, amount })
  }
}

impl Mul<Amount> for Balance {
  type Output = Option<Balance>;
  fn mul(self, other: Amount) -> Option<Balance> {
    (self.amount * other).map(|amount| Balance { coin: self.coin, amount })
  }
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
