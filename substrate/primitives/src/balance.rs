use core::ops::{Add, Sub, Mul};
use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::coin::{ExternalCoin, Coin};

/// The type internally used to represent amounts.
// TODO: https://github.com/rust-lang/rust/issues/8995
pub type AmountRepr = u64;

/// A wrapper used to represent amounts.
///
/// All arithmetic with this type is checked, forcing the caller to consider (under/over)flow.
#[rustfmt::skip] // Prevent rustfmt from expanding the following `derive`s into a monstrosity
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[derive(Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct Amount(pub AmountRepr);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(Amount);

#[expect(clippy::derivable_impls)] // Being explicit is appreciated
impl Default for Amount {
  fn default() -> Self {
    Amount(0)
  }
}

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

/// An [`ExternalCoin`] and an [`Amount`], forming a balance for an external coin.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct ExternalBalance {
  /// The coin this is a balance for.
  pub coin: ExternalCoin,
  /// The amount of this balance.
  pub amount: Amount,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(ExternalBalance);
#[cfg(feature = "scale")]
impl scale::EncodeLike<Balance> for ExternalBalance {}

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

/// A [`Coin`] and an [`Amount`], forming a balance for a coin.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
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

#[test]
fn amount() {
  assert_eq!(Amount(0), Amount(0));
  assert_ne!(Amount(0), Amount(1));
  assert!(Amount(0) < Amount(1));
  assert!(Amount(1) > Amount(0));

  use rand_core::{RngCore as _, OsRng};

  let amount = Amount(OsRng.next_u64());

  assert_eq!(
    Amount::deserialize_reader(&mut borsh::to_vec(&amount).unwrap().as_slice()).unwrap(),
    amount
  );

  #[cfg(feature = "scale")]
  {
    use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};
    assert_eq!(amount.encode(), borsh::to_vec(&amount).unwrap());
    assert_eq!(Amount::decode_all(&mut amount.encode().as_slice()).unwrap(), amount);
    assert_eq!(Amount(u64::MAX).encode().len(), Amount::max_encoded_len());
  }
}

#[test]
fn external_balance() {
  use rand_core::{RngCore as _, OsRng};

  for coin in ExternalCoin::all() {
    let amount = OsRng.next_u64();
    let balance = ExternalBalance { coin, amount: Amount(amount) };
    assert_eq!(ExternalBalance::try_from(Balance::from(balance)).unwrap(), balance);

    assert_eq!(
      ExternalBalance::deserialize_reader(&mut borsh::to_vec(&balance).unwrap().as_slice())
        .unwrap(),
      balance
    );

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _};
      assert_eq!(balance.encode(), borsh::to_vec(&balance).unwrap());
      assert_eq!(ExternalBalance::decode_all(&mut balance.encode().as_slice()).unwrap(), balance);
      assert_eq!(Balance::from(balance).encode(), balance.encode());
    }
  }
}

#[test]
fn balance() {
  use rand_core::{RngCore as _, OsRng};

  for coin in Coin::all() {
    let amount = OsRng.next_u64();
    let balance = Balance { coin, amount: Amount(amount) };

    assert_eq!(
      Balance::deserialize_reader(&mut borsh::to_vec(&balance).unwrap().as_slice()).unwrap(),
      balance
    );

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _};
      assert_eq!(balance.encode(), borsh::to_vec(&balance).unwrap());
      assert_eq!(Balance::decode_all(&mut balance.encode().as_slice()).unwrap(), balance);
    }
  }
}
