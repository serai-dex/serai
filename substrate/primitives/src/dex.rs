use alloc::{vec, vec::Vec};

use crate::{
  coin::{ExternalCoin, Coin},
  balance::Amount,
};

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
  /// Establish the premise of a swap.
  ///
  /// This will return `None` if not exactly one coin is `Coin::Serai`.
  pub fn establish(coin_in: Coin, coin_out: Coin) -> Option<Self> {
    if !((coin_in == Coin::Serai) ^ (coin_out == Coin::Serai)) {
      None?;
    }

    Some(match coin_in {
      Coin::Serai => match coin_out {
        Coin::Serai => unreachable!("prior checked exactly one was `Coin::Serai`"),
        Coin::External(coin) => Premise::FromSerai { to: coin },
      },
      Coin::External(coin) => Premise::ToSerai { from: coin },
    })
  }

  /// Establish the route for a swap.
  ///
  /// This will return `None` if the coin from is the coin to.
  pub fn route(coin_in: Coin, coin_out: Coin) -> Option<Vec<Self>> {
    if coin_in == coin_out {
      None?;
    }
    Some(if (coin_in == Coin::Serai) ^ (coin_out == Coin::Serai) {
      vec![Self::establish(coin_in, coin_out).expect("sri ^ sri")]
    } else {
      // Since they aren't both `Coin::Serai`, and not just one is, neither are
      vec![
        Self::establish(coin_in, Coin::Serai).expect("sri ^ sri #1"),
        Self::establish(Coin::Serai, coin_out).expect("sri ^ sri #2"),
      ]
    })
  }

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
    let required_proposed_in_reserve = current_k.div_ceil(u128::from(proposed_out_reserve));
    let required_proposed_in_reserve =
      u64::try_from(required_proposed_in_reserve).map_err(|_| Error::Overflow)?;
    let amount_in =
      Amount(required_proposed_in_reserve.checked_sub(in_reserve).ok_or(Error::Overflow)?);

    self.validate(reserves, amount_in, amount_out)?;

    Ok(amount_in)
  }
}
