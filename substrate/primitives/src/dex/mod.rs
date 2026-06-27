use crate::{
  coin::{ExternalCoin, Coin},
  balance::Amount,
};

mod routing;

/// An error incurred with the DEX.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
  /// An arithmetic overflow occurred.
  Overflow,
  /// An arithmetic underflow occured.
  Underflow,
  /// The `x * y = k` invariant was violated.
  KInvariant,
}

/// The premise of a swap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Premise {
  /// A swap to SRI.
  ToSerai {
    /// The coin swapped from.
    from: ExternalCoin,
  },
  /// A swap from SRI.
  FromSerai {
    /// The coin swapped to.
    to: ExternalCoin,
  },
}

impl Premise {
  /// Fetch the coin _in_ for the swap.
  pub fn r#in(self) -> Coin {
    match self {
      Premise::ToSerai { from } => from.into(),
      Premise::FromSerai { .. } => Coin::Serai,
    }
  }

  /// Fetch the coin _out_ from the swap.
  pub fn out(self) -> Coin {
    match self {
      Premise::ToSerai { .. } => Coin::Serai,
      Premise::FromSerai { to } => to.into(),
    }
  }

  /// Fetch the external coin present within the swap.
  pub fn external_coin(self) -> ExternalCoin {
    match self {
      Premise::ToSerai { from: external_coin } | Premise::FromSerai { to: external_coin } => {
        external_coin
      }
    }
  }
}

/// The reserves for a liquidity pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reserves {
  /// The amount of SRI already present.
  pub sri: Amount,
  /// The amount of the external coin already present.
  pub external_coin: Amount,
}

impl Reserves {
  /// The product of two amounts.
  ///
  /// This is intended to be used as the famous `x * y = k` formula's implementation.
  fn product(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
  }

  /// Decompose this into `(in_reserve, out_reserve)` given the direction for a swap.
  fn as_in_out(self, premise: Premise) -> (u64, u64) {
    match premise {
      Premise::ToSerai { .. } => (self.external_coin.0, self.sri.0),
      Premise::FromSerai { .. } => (self.sri.0, self.external_coin.0),
    }
  }
}

impl Premise {
  /// Validate the following swap may be performed.
  ///
  /// Validation of the amounts occur via the `x * y = k` formula popularized with Uniswap V2,
  /// itself licensed under the GPL.
  ///
  /// For more information, please see the following links:
  ///
  /// <https://docs.uniswap.org/contracts/v2/concepts/protocol-overview/how-uniswap-works>
  ///
  /// <https://github.com/Uniswap/v2-core/blob/4dd59067c76dea4a0e8e4bfdda41877a6b16dedc>
  fn validate(
    self,
    reserves: Reserves,
    amount_in: Amount,
    amount_out: Amount,
  ) -> Result<(), Error> {
    let (in_reserve, out_reserve) = reserves.as_in_out(self);
    let current_k = Reserves::product(in_reserve, out_reserve);
    let proposed_k = Reserves::product(
      in_reserve.checked_add(amount_in.0).ok_or(Error::Overflow)?,
      out_reserve.checked_sub(amount_out.0).ok_or(Error::Underflow)?,
    );
    if proposed_k < current_k {
      Err(Error::KInvariant)?;
    }
    Ok(())
  }

  /// Quote a swap for an amount in.
  pub fn quote_for_in(self, reserves: Reserves, amount_in: Amount) -> Result<Amount, Error> {
    let (in_reserve, out_reserve) = reserves.as_in_out(self);
    let current_k = Reserves::product(in_reserve, out_reserve);
    let proposed_in_reserve = u128::from(in_reserve) + u128::from(amount_in.0);
    if proposed_in_reserve == 0 {
      Err(Error::KInvariant)?;
    }
    let required_proposed_out_reserve = current_k.div_ceil(proposed_in_reserve);
    // If this does not fit in a `u64`, the following substraction would have underflowed
    let required_proposed_out_reserve =
      u64::try_from(required_proposed_out_reserve).map_err(|_| Error::Underflow)?;
    let amount_out =
      Amount(out_reserve.checked_sub(required_proposed_out_reserve).ok_or(Error::Underflow)?);

    // Ensure this passes validation using a consistent, traditionally presented function
    self.validate(reserves, amount_in, amount_out)?;

    Ok(amount_out)
  }

  /// Quote a swap for an amount out.
  pub fn quote_for_out(self, reserves: Reserves, amount_out: Amount) -> Result<Amount, Error> {
    let (in_reserve, out_reserve) = reserves.as_in_out(self);
    let current_k = Reserves::product(in_reserve, out_reserve);
    let proposed_out_reserve = out_reserve.checked_sub(amount_out.0).ok_or(Error::Underflow)?;
    if proposed_out_reserve == 0 {
      Err(Error::KInvariant)?;
    }
    let required_proposed_in_reserve = current_k.div_ceil(u128::from(proposed_out_reserve));
    let required_proposed_in_reserve =
      u64::try_from(required_proposed_in_reserve).map_err(|_| Error::Overflow)?;
    let amount_in =
      Amount(required_proposed_in_reserve.checked_sub(in_reserve).ok_or(Error::Overflow)?);

    self.validate(reserves, amount_in, amount_out)?;

    Ok(amount_in)
  }
}

#[test]
fn reserves() {
  // Ensure `Reserves::product` does not panic
  let _ = Reserves::product(0, 0);
  let _ = Reserves::product(u64::MAX, u64::MAX);

  // Test `Reserves::as_in_out`
  assert_eq!(
    (Reserves { sri: Amount(1), external_coin: Amount(2) })
      .as_in_out(Premise::establish(Coin::Serai, Coin::from(ExternalCoin::Bitcoin)).unwrap()),
    (1, 2)
  );
  assert_eq!(
    (Reserves { sri: Amount(1), external_coin: Amount(2) })
      .as_in_out(Premise::establish(Coin::from(ExternalCoin::Bitcoin), Coin::Serai).unwrap()),
    (2, 1)
  );
}

#[test]
fn quote_sanity() {
  let reserves = Reserves { sri: Amount(100_000), external_coin: Amount(10_000) };

  let sri_in = Premise::establish(Coin::Serai, Coin::from(ExternalCoin::Bitcoin)).unwrap();
  assert!(sri_in.quote_for_in(reserves, Amount(10_000)).unwrap() < Amount(1_000));
  assert!(sri_in.quote_for_out(reserves, Amount(1_000)).unwrap() > Amount(10_000));

  let sri_out = Premise::establish(Coin::from(ExternalCoin::Bitcoin), Coin::Serai).unwrap();
  assert!(sri_out.quote_for_in(reserves, Amount(1_000)).unwrap() < Amount(10_000));
  assert!(sri_out.quote_for_out(reserves, Amount(10_000)).unwrap() > Amount(1_000));
}

#[test]
fn quote_does_not_panic() {
  use rand_core::{RngCore as _, OsRng};

  // Test exceptional cases, as recommended in https://github.com/serai-dex/serai/issues/746
  {
    let reserves = Reserves { sri: Amount(100_000), external_coin: Amount(10_000) };
    let sri_in = Premise::establish(Coin::Serai, Coin::from(ExternalCoin::Bitcoin)).unwrap();
    for amount in [Amount(0), reserves.sri, reserves.external_coin, Amount(u64::MAX - 1)] {
      for amount in [amount, Amount(amount.0 + 1)] {
        let _ = sri_in.quote_for_in(reserves, amount);
        let _ = sri_in.quote_for_out(reserves, amount);
      }
    }
  }

  // Fuzz test random values to see if a panic occurs
  for _ in 0 .. 100_000 {
    let reserves =
      Reserves { sri: Amount(OsRng.next_u64()), external_coin: Amount(OsRng.next_u64()) };

    let sri_in = Premise::establish(Coin::Serai, Coin::from(ExternalCoin::Bitcoin)).unwrap();
    let _ = sri_in.quote_for_in(reserves, Amount(OsRng.next_u64()));
    let _ = sri_in.quote_for_out(reserves, Amount(OsRng.next_u64()));

    let sri_out = Premise::establish(Coin::from(ExternalCoin::Bitcoin), Coin::Serai).unwrap();
    let _ = sri_out.quote_for_in(reserves, Amount(OsRng.next_u64()));
    let _ = sri_out.quote_for_out(reserves, Amount(OsRng.next_u64()));
  }
}
