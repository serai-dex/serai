use core::ops::{Add, Neg, Sub, Mul, Rem};
use std_shims::{vec, vec::Vec};

use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

use group::ff::PrimeField;

#[derive(Clone, Copy, PartialEq, Debug)]
struct CoefficientIndex {
  y_pow: u64,
  x_pow: u64,
}
impl ConditionallySelectable for CoefficientIndex {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    Self {
      y_pow: <_>::conditional_select(&a.y_pow, &b.y_pow, choice),
      x_pow: <_>::conditional_select(&a.x_pow, &b.x_pow, choice),
    }
  }
}
impl ConstantTimeEq for CoefficientIndex {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.y_pow.ct_eq(&other.y_pow) & self.x_pow.ct_eq(&other.x_pow)
  }
}
impl ConstantTimeGreater for CoefficientIndex {
  fn ct_gt(&self, other: &Self) -> Choice {
    self.y_pow.ct_gt(&other.y_pow) |
      (self.y_pow.ct_eq(&other.y_pow) & self.x_pow.ct_gt(&other.x_pow))
  }
}

/// A structure representing a Polynomial with x^i, y^i, and y^i * x^j terms.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Poly<F: From<u64> + Zeroize + PrimeField> {
  /// c\[i] * y^(i + 1)
  pub y_coefficients: Vec<F>,
  /// c\[i]\[j] * y^(i + 1) x^(j + 1)
  pub yx_coefficients: Vec<Vec<F>>,
  /// c\[i] * x^(i + 1)
  pub x_coefficients: Vec<F>,
  /// Coefficient for x^0, y^0, and x^0 y^0 (the coefficient for 1)
  pub zero_coefficient: F,
}

impl<F: From<u64> + Zeroize + PrimeField> PartialEq for Poly<F> {
  // This is not constant time and is not meant to be
  fn eq(&self, b: &Poly<F>) -> bool {
    {
      let mutual_y_coefficients = self.y_coefficients.len().min(b.y_coefficients.len());
      if self.y_coefficients[.. mutual_y_coefficients] != b.y_coefficients[.. mutual_y_coefficients]
      {
        return false;
      }
      for coeff in &self.y_coefficients[mutual_y_coefficients ..] {
        if *coeff != F::ZERO {
          return false;
        }
      }
      for coeff in &b.y_coefficients[mutual_y_coefficients ..] {
        if *coeff != F::ZERO {
          return false;
        }
      }
    }

    {
      for (i, yx_coeffs) in self.yx_coefficients.iter().enumerate() {
        for (j, coeff) in yx_coeffs.iter().enumerate() {
          if coeff != b.yx_coefficients.get(i).unwrap_or(&vec![]).get(j).unwrap_or(&F::ZERO) {
            return false;
          }
        }
      }
      // Run from the other perspective in case other is longer than self
      for (i, yx_coeffs) in b.yx_coefficients.iter().enumerate() {
        for (j, coeff) in yx_coeffs.iter().enumerate() {
          if coeff != self.yx_coefficients.get(i).unwrap_or(&vec![]).get(j).unwrap_or(&F::ZERO) {
            return false;
          }
        }
      }
    }

    {
      let mutual_x_coefficients = self.x_coefficients.len().min(b.x_coefficients.len());
      if self.x_coefficients[.. mutual_x_coefficients] != b.x_coefficients[.. mutual_x_coefficients]
      {
        return false;
      }
      for coeff in &self.x_coefficients[mutual_x_coefficients ..] {
        if *coeff != F::ZERO {
          return false;
        }
      }
      for coeff in &b.x_coefficients[mutual_x_coefficients ..] {
        if *coeff != F::ZERO {
          return false;
        }
      }
    }

    self.zero_coefficient == b.zero_coefficient
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Poly<F> {
  /// A polynomial for zero.
  pub(crate) fn zero() -> Self {
    Poly {
      y_coefficients: vec![],
      yx_coefficients: vec![],
      x_coefficients: vec![],
      zero_coefficient: F::ZERO,
    }
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Add<&Self> for Poly<F> {
  type Output = Self;

  fn add(mut self, other: &Self) -> Self {
    // Expand to be the neeeded size
    while self.y_coefficients.len() < other.y_coefficients.len() {
      self.y_coefficients.push(F::ZERO);
    }
    while self.yx_coefficients.len() < other.yx_coefficients.len() {
      self.yx_coefficients.push(vec![]);
    }
    for i in 0 .. other.yx_coefficients.len() {
      while self.yx_coefficients[i].len() < other.yx_coefficients[i].len() {
        self.yx_coefficients[i].push(F::ZERO);
      }
    }
    while self.x_coefficients.len() < other.x_coefficients.len() {
      self.x_coefficients.push(F::ZERO);
    }

    // Perform the addition
    for (i, coeff) in other.y_coefficients.iter().enumerate() {
      self.y_coefficients[i] += coeff;
    }
    for (i, coeffs) in other.yx_coefficients.iter().enumerate() {
      for (j, coeff) in coeffs.iter().enumerate() {
        self.yx_coefficients[i][j] += coeff;
      }
    }
    for (i, coeff) in other.x_coefficients.iter().enumerate() {
      self.x_coefficients[i] += coeff;
    }
    self.zero_coefficient += other.zero_coefficient;

    self
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Neg for Poly<F> {
  type Output = Self;

  fn neg(mut self) -> Self {
    for y_coeff in self.y_coefficients.iter_mut() {
      *y_coeff = -*y_coeff;
    }
    for yx_coeffs in self.yx_coefficients.iter_mut() {
      for yx_coeff in yx_coeffs.iter_mut() {
        *yx_coeff = -*yx_coeff;
      }
    }
    for x_coeff in self.x_coefficients.iter_mut() {
      *x_coeff = -*x_coeff;
    }
    self.zero_coefficient = -self.zero_coefficient;

    self
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Sub for Poly<F> {
  type Output = Self;

  fn sub(self, other: Self) -> Self {
    self + &-other
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Mul<F> for Poly<F> {
  type Output = Self;

  fn mul(mut self, scalar: F) -> Self {
    for y_coeff in self.y_coefficients.iter_mut() {
      *y_coeff *= scalar;
    }
    for coeffs in self.yx_coefficients.iter_mut() {
      for coeff in coeffs.iter_mut() {
        *coeff *= scalar;
      }
    }
    for x_coeff in self.x_coefficients.iter_mut() {
      *x_coeff *= scalar;
    }
    self.zero_coefficient *= scalar;
    self
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Poly<F> {
  #[must_use]
  fn shift_by_x(mut self, power_of_x: usize) -> Self {
    if power_of_x == 0 {
      return self;
    }

    // Shift up every x coefficient
    for _ in 0 .. power_of_x {
      self.x_coefficients.insert(0, F::ZERO);
      for yx_coeffs in &mut self.yx_coefficients {
        yx_coeffs.insert(0, F::ZERO);
      }
    }

    // Move the zero coefficient
    self.x_coefficients[power_of_x - 1] = self.zero_coefficient;
    self.zero_coefficient = F::ZERO;

    // Move the y coefficients
    // Start by creating yx coefficients with the necessary powers of x
    let mut yx_coefficients_to_push = vec![];
    while yx_coefficients_to_push.len() < power_of_x {
      yx_coefficients_to_push.push(F::ZERO);
    }
    // Now, ensure the yx coefficients has the slots for the y coefficients we're moving
    while self.yx_coefficients.len() < self.y_coefficients.len() {
      self.yx_coefficients.push(yx_coefficients_to_push.clone());
    }
    // Perform the move
    for (i, y_coeff) in self.y_coefficients.drain(..).enumerate() {
      self.yx_coefficients[i][power_of_x - 1] = y_coeff;
    }

    self
  }

  #[must_use]
  fn shift_by_y(mut self, power_of_y: usize) -> Self {
    if power_of_y == 0 {
      return self;
    }

    // Shift up every y coefficient
    for _ in 0 .. power_of_y {
      self.y_coefficients.insert(0, F::ZERO);
      self.yx_coefficients.insert(0, vec![]);
    }

    // Move the zero coefficient
    self.y_coefficients[power_of_y - 1] = self.zero_coefficient;
    self.zero_coefficient = F::ZERO;

    // Move the x coefficients
    core::mem::swap(&mut self.yx_coefficients[power_of_y - 1], &mut self.x_coefficients);
    self.x_coefficients = vec![];

    self
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Mul<&Poly<F>> for Poly<F> {
  type Output = Self;

  fn mul(self, other: &Self) -> Self {
    let mut res = self.clone() * other.zero_coefficient;

    for (i, y_coeff) in other.y_coefficients.iter().enumerate() {
      let scaled = self.clone() * *y_coeff;
      res = res + &scaled.shift_by_y(i + 1);
    }

    for (y_i, yx_coeffs) in other.yx_coefficients.iter().enumerate() {
      for (x_i, yx_coeff) in yx_coeffs.iter().enumerate() {
        let scaled = self.clone() * *yx_coeff;
        res = res + &scaled.shift_by_y(y_i + 1).shift_by_x(x_i + 1);
      }
    }

    for (i, x_coeff) in other.x_coefficients.iter().enumerate() {
      let scaled = self.clone() * *x_coeff;
      res = res + &scaled.shift_by_x(i + 1);
    }

    res
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Poly<F> {
  // The leading y coefficient and associated x coefficient.
  fn leading_coefficient(&self) -> (usize, usize) {
    if self.y_coefficients.len() > self.yx_coefficients.len() {
      (self.y_coefficients.len(), 0)
    } else if !self.yx_coefficients.is_empty() {
      (self.yx_coefficients.len(), self.yx_coefficients.last().unwrap().len())
    } else {
      (0, self.x_coefficients.len())
    }
  }

  /// Returns the highest non-zero coefficient greater than the specified coefficient.
  ///
  /// If no non-zero coefficient is greater than the specified coefficient, this will return
  /// (0, 0).
  fn greater_than_or_equal_coefficient(
    &self,
    greater_than_or_equal: &CoefficientIndex,
  ) -> CoefficientIndex {
    let mut leading_coefficient = CoefficientIndex { y_pow: 0, x_pow: 0 };
    for (y_pow_sub_one, coeff) in self.y_coefficients.iter().enumerate() {
      let y_pow = u64::try_from(y_pow_sub_one + 1).unwrap();
      let coeff_is_non_zero = !coeff.is_zero();
      let potential = CoefficientIndex { y_pow, x_pow: 0 };
      leading_coefficient = <_>::conditional_select(
        &leading_coefficient,
        &potential,
        coeff_is_non_zero &
          potential.ct_gt(&leading_coefficient) &
          (potential.ct_gt(greater_than_or_equal) | potential.ct_eq(greater_than_or_equal)),
      );
    }
    for (y_pow_sub_one, yx_coefficients) in self.yx_coefficients.iter().enumerate() {
      let y_pow = u64::try_from(y_pow_sub_one + 1).unwrap();
      for (x_pow_sub_one, coeff) in yx_coefficients.iter().enumerate() {
        let x_pow = u64::try_from(x_pow_sub_one + 1).unwrap();
        let coeff_is_non_zero = !coeff.is_zero();
        let potential = CoefficientIndex { y_pow, x_pow };
        leading_coefficient = <_>::conditional_select(
          &leading_coefficient,
          &potential,
          coeff_is_non_zero &
            potential.ct_gt(&leading_coefficient) &
            (potential.ct_gt(greater_than_or_equal) | potential.ct_eq(greater_than_or_equal)),
        );
      }
    }
    for (x_pow_sub_one, coeff) in self.x_coefficients.iter().enumerate() {
      let x_pow = u64::try_from(x_pow_sub_one + 1).unwrap();
      let coeff_is_non_zero = !coeff.is_zero();
      let potential = CoefficientIndex { y_pow: 0, x_pow };
      leading_coefficient = <_>::conditional_select(
        &leading_coefficient,
        &potential,
        coeff_is_non_zero &
          potential.ct_gt(&leading_coefficient) &
          (potential.ct_gt(greater_than_or_equal) | potential.ct_eq(greater_than_or_equal)),
      );
    }
    leading_coefficient
  }

  /// Perform multiplication mod `modulus`.
  #[must_use]
  pub(crate) fn mul_mod(self, other: &Self, modulus: &Self) -> Self {
    (self * other) % modulus
  }

  /// Perform division, returning the result and remainder.
  ///
  /// This function is constant time to the structure of the numerator and denominator. The actual
  /// value of the coefficients will not introduce timing differences.
  ///
  /// Panics upon division by a polynomial where all coefficients are zero.
  #[must_use]
  pub(crate) fn div_rem(self, denominator: &Self) -> (Self, Self) {
    // These functions have undefined behavior if this isn't a valid index for this poly
    fn ct_get<F: From<u64> + Zeroize + PrimeField>(poly: &Poly<F>, index: CoefficientIndex) -> F {
      let mut res = poly.zero_coefficient;
      for (y_pow_sub_one, coeff) in poly.y_coefficients.iter().enumerate() {
        res = <_>::conditional_select(
          &res,
          coeff,
          index
            .ct_eq(&CoefficientIndex { y_pow: (y_pow_sub_one + 1).try_into().unwrap(), x_pow: 0 }),
        );
      }
      for (y_pow_sub_one, coeffs) in poly.yx_coefficients.iter().enumerate() {
        for (x_pow_sub_one, coeff) in coeffs.iter().enumerate() {
          res = <_>::conditional_select(
            &res,
            coeff,
            index.ct_eq(&CoefficientIndex {
              y_pow: (y_pow_sub_one + 1).try_into().unwrap(),
              x_pow: (x_pow_sub_one + 1).try_into().unwrap(),
            }),
          );
        }
      }
      for (x_pow_sub_one, coeff) in poly.x_coefficients.iter().enumerate() {
        res = <_>::conditional_select(
          &res,
          coeff,
          index
            .ct_eq(&CoefficientIndex { y_pow: 0, x_pow: (x_pow_sub_one + 1).try_into().unwrap() }),
        );
      }
      res
    }

    fn ct_set<F: From<u64> + Zeroize + PrimeField>(
      poly: &mut Poly<F>,
      index: CoefficientIndex,
      value: F,
    ) {
      for (y_pow_sub_one, coeff) in poly.y_coefficients.iter_mut().enumerate() {
        *coeff = <_>::conditional_select(
          coeff,
          &value,
          index
            .ct_eq(&CoefficientIndex { y_pow: (y_pow_sub_one + 1).try_into().unwrap(), x_pow: 0 }),
        );
      }
      for (y_pow_sub_one, coeffs) in poly.yx_coefficients.iter_mut().enumerate() {
        for (x_pow_sub_one, coeff) in coeffs.iter_mut().enumerate() {
          *coeff = <_>::conditional_select(
            coeff,
            &value,
            index.ct_eq(&CoefficientIndex {
              y_pow: (y_pow_sub_one + 1).try_into().unwrap(),
              x_pow: (x_pow_sub_one + 1).try_into().unwrap(),
            }),
          );
        }
      }
      for (x_pow_sub_one, coeff) in poly.x_coefficients.iter_mut().enumerate() {
        *coeff = <_>::conditional_select(
          coeff,
          &value,
          index
            .ct_eq(&CoefficientIndex { y_pow: 0, x_pow: (x_pow_sub_one + 1).try_into().unwrap() }),
        );
      }
      poly.zero_coefficient = <_>::conditional_select(
        &poly.zero_coefficient,
        &value,
        index.ct_eq(&CoefficientIndex { y_pow: 0, x_pow: 0 }),
      );
    }

    fn conditional_select_poly<F: From<u64> + Zeroize + PrimeField>(
      mut a: Poly<F>,
      mut b: Poly<F>,
      choice: Choice,
    ) -> Poly<F> {
      let pad_to = |a: &mut Poly<F>, b: &Poly<F>| {
        while a.x_coefficients.len() < b.x_coefficients.len() {
          a.x_coefficients.push(F::ZERO);
        }
        while a.yx_coefficients.len() < b.yx_coefficients.len() {
          a.yx_coefficients.push(vec![]);
        }
        for (a, b) in a.yx_coefficients.iter_mut().zip(&b.yx_coefficients) {
          while a.len() < b.len() {
            a.push(F::ZERO);
          }
        }
        while a.y_coefficients.len() < b.y_coefficients.len() {
          a.y_coefficients.push(F::ZERO);
        }
      };
      // Pad these to be the same size/layout as each other
      pad_to(&mut a, &b);
      pad_to(&mut b, &a);

      let mut res = Poly::zero();
      for (a, b) in a.y_coefficients.iter().zip(&b.y_coefficients) {
        res.y_coefficients.push(<_>::conditional_select(a, b, choice));
      }
      for (a, b) in a.yx_coefficients.iter().zip(&b.yx_coefficients) {
        let mut yx_coefficients = Vec::with_capacity(a.len());
        for (a, b) in a.iter().zip(b) {
          yx_coefficients.push(<_>::conditional_select(a, b, choice))
        }
        res.yx_coefficients.push(yx_coefficients);
      }
      for (a, b) in a.x_coefficients.iter().zip(&b.x_coefficients) {
        res.x_coefficients.push(<_>::conditional_select(a, b, choice));
      }
      res.zero_coefficient =
        <_>::conditional_select(&a.zero_coefficient, &b.zero_coefficient, choice);

      res
    }

    // The following long division algorithm only works if the denominator actually has a variable
    // If the denominator isn't variable to anything, short-circuit to scalar 'division'
    // This is safe as `leading_coefficient` is based on the structure, not the values, of the poly
    let denominator_leading_coefficient = denominator.leading_coefficient();
    if denominator_leading_coefficient == (0, 0) {
      return (self * denominator.zero_coefficient.invert().unwrap(), Poly::zero());
    }

    // The structure of the quotient, which is the the numerator with all coefficients set to 0
    let mut quotient_structure = Poly {
      y_coefficients: vec![F::ZERO; self.y_coefficients.len()],
      yx_coefficients: self.yx_coefficients.clone(),
      x_coefficients: vec![F::ZERO; self.x_coefficients.len()],
      zero_coefficient: F::ZERO,
    };
    for coeff in quotient_structure
      .yx_coefficients
      .iter_mut()
      .flat_map(|yx_coefficients| yx_coefficients.iter_mut())
    {
      *coeff = F::ZERO;
    }

    // Calculate the amount of iterations we need to perform
    let iterations = self.y_coefficients.len() +
      self.yx_coefficients.iter().map(|yx_coefficients| yx_coefficients.len()).sum::<usize>() +
      self.x_coefficients.len();

    // Find the highest non-zero coefficient in the denominator
    // This is the coefficient which we actually perform division with
    let denominator_dividing_coefficient =
      denominator.greater_than_or_equal_coefficient(&CoefficientIndex { y_pow: 0, x_pow: 0 });
    let denominator_dividing_coefficient_inv =
      ct_get(denominator, denominator_dividing_coefficient).invert().unwrap();

    let mut quotient = quotient_structure.clone();
    let mut remainder = self.clone();
    for _ in 0 .. iterations {
      // Find the numerator coefficient we're clearing
      // This will be (0, 0) if we aren't clearing a coefficient
      let numerator_coefficient =
        remainder.greater_than_or_equal_coefficient(&denominator_dividing_coefficient);

      // We only apply the effects of this iteration if the numerator's coefficient is actually >=
      let meaningful_iteration = numerator_coefficient.ct_gt(&denominator_dividing_coefficient) |
        numerator_coefficient.ct_eq(&denominator_dividing_coefficient);

      // 1) Find the scalar `q` such that the leading coefficient of `q * denominator` is equal to
      //    the leading coefficient of self.
      let numerator_coefficient_value = ct_get(&remainder, numerator_coefficient);
      let q = numerator_coefficient_value * denominator_dividing_coefficient_inv;

      // 2) Calculate the full term of the quotient by scaling with the necessary powers of y/x
      let proper_powers_of_yx = CoefficientIndex {
        y_pow: numerator_coefficient.y_pow.wrapping_sub(denominator_dividing_coefficient.y_pow),
        x_pow: numerator_coefficient.x_pow.wrapping_sub(denominator_dividing_coefficient.x_pow),
      };
      let fallabck_powers_of_yx = CoefficientIndex { y_pow: 0, x_pow: 0 };
      let mut quotient_term = quotient_structure.clone();
      ct_set(
        &mut quotient_term,
        // If the numerator coefficient isn't >=, proper_powers_of_yx will have garbage in them
        <_>::conditional_select(&fallabck_powers_of_yx, &proper_powers_of_yx, meaningful_iteration),
        q,
      );

      let quotient_if_meaningful = quotient.clone() + &quotient_term;
      quotient = conditional_select_poly(quotient, quotient_if_meaningful, meaningful_iteration);

      // 3) Remove what we've divided out from self
      let remainder_if_meaningful = remainder.clone() - (quotient_term * denominator);
      remainder = conditional_select_poly(remainder, remainder_if_meaningful, meaningful_iteration);
    }

    quotient = conditional_select_poly(
      quotient,
      // If the dividing coefficient was for y**0 x**0, we return the poly scaled by its inverse
      self * denominator_dividing_coefficient_inv,
      denominator_dividing_coefficient.ct_eq(&CoefficientIndex { y_pow: 0, x_pow: 0 }),
    );
    remainder = conditional_select_poly(
      remainder,
      // If the dividing coefficient was for y**0 x**0, we're able to perfectly divide and there's
      // no remainder
      Poly::zero(),
      denominator_dividing_coefficient.ct_eq(&CoefficientIndex { y_pow: 0, x_pow: 0 }),
    );

    // Clear any junk terms out of the remainder which are less than the denominator
    let denominator_leading_coefficient = CoefficientIndex {
      y_pow: denominator_leading_coefficient.0.try_into().unwrap(),
      x_pow: denominator_leading_coefficient.1.try_into().unwrap(),
    };
    if denominator_leading_coefficient != (CoefficientIndex { y_pow: 0, x_pow: 0 }) {
      while {
        let index =
          CoefficientIndex { y_pow: remainder.y_coefficients.len().try_into().unwrap(), x_pow: 0 };
        bool::from(
          index.ct_gt(&denominator_leading_coefficient) |
            index.ct_eq(&denominator_leading_coefficient),
        )
      } {
        let popped = remainder.y_coefficients.pop();
        debug_assert_eq!(popped, Some(F::ZERO));
      }
      while {
        let index = CoefficientIndex {
          y_pow: remainder.yx_coefficients.len().try_into().unwrap(),
          x_pow: remainder
            .yx_coefficients
            .last()
            .map(|yx_coefficients| yx_coefficients.len())
            .unwrap_or(0)
            .try_into()
            .unwrap(),
        };
        bool::from(
          index.ct_gt(&denominator_leading_coefficient) |
            index.ct_eq(&denominator_leading_coefficient),
        )
      } {
        let popped = remainder.yx_coefficients.last_mut().unwrap().pop();
        // This may have been `vec![]`
        if let Some(popped) = popped {
          debug_assert_eq!(popped, F::ZERO);
        }
        if remainder.yx_coefficients.last().unwrap().is_empty() {
          let popped = remainder.yx_coefficients.pop();
          debug_assert_eq!(popped, Some(vec![]));
        }
      }
      while {
        let index =
          CoefficientIndex { y_pow: 0, x_pow: remainder.x_coefficients.len().try_into().unwrap() };
        bool::from(
          index.ct_gt(&denominator_leading_coefficient) |
            index.ct_eq(&denominator_leading_coefficient),
        )
      } {
        let popped = remainder.x_coefficients.pop();
        debug_assert_eq!(popped, Some(F::ZERO));
      }
    }

    (quotient, remainder)
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Rem<&Self> for Poly<F> {
  type Output = Self;

  fn rem(self, modulus: &Self) -> Self {
    self.div_rem(modulus).1
  }
}

impl<F: From<u64> + Zeroize + PrimeField> Poly<F> {
  /// Evaluate this polynomial with the specified x/y values.
  ///
  /// Panics on polynomials with terms whose powers exceed 2^64.
  #[must_use]
  pub fn eval(&self, x: F, y: F) -> F {
    let mut res = self.zero_coefficient;
    for (pow, coeff) in
      self.y_coefficients.iter().enumerate().map(|(i, v)| (u64::try_from(i + 1).unwrap(), v))
    {
      res += y.pow([pow]) * coeff;
    }
    for (y_pow, coeffs) in
      self.yx_coefficients.iter().enumerate().map(|(i, v)| (u64::try_from(i + 1).unwrap(), v))
    {
      let y_pow = y.pow([y_pow]);
      for (x_pow, coeff) in
        coeffs.iter().enumerate().map(|(i, v)| (u64::try_from(i + 1).unwrap(), v))
      {
        res += y_pow * x.pow([x_pow]) * coeff;
      }
    }
    for (pow, coeff) in
      self.x_coefficients.iter().enumerate().map(|(i, v)| (u64::try_from(i + 1).unwrap(), v))
    {
      res += x.pow([pow]) * coeff;
    }
    res
  }

  /// Differentiate a polynomial, reduced by a modulus with a leading y term y^2 x^0, by x and y.
  ///
  /// This function has undefined behavior if unreduced.
  #[must_use]
  pub fn differentiate(&self) -> (Poly<F>, Poly<F>) {
    // Differentation by x practically involves:
    // - Dropping everything without an x component
    // - Shifting everything down a power of x
    // - Multiplying the new coefficient by the power it prior was used with
    let diff_x = {
      let mut diff_x = Poly {
        y_coefficients: vec![],
        yx_coefficients: vec![],
        x_coefficients: vec![],
        zero_coefficient: F::ZERO,
      };
      if !self.x_coefficients.is_empty() {
        let mut x_coeffs = self.x_coefficients.clone();
        diff_x.zero_coefficient = x_coeffs.remove(0);
        diff_x.x_coefficients = x_coeffs;

        let mut prior_x_power = F::from(2);
        for x_coeff in &mut diff_x.x_coefficients {
          *x_coeff *= prior_x_power;
          prior_x_power += F::ONE;
        }
      }

      if !self.yx_coefficients.is_empty() {
        let mut yx_coeffs = self.yx_coefficients[0].clone();
        if !yx_coeffs.is_empty() {
          diff_x.y_coefficients = vec![yx_coeffs.remove(0)];
          diff_x.yx_coefficients = vec![yx_coeffs];

          let mut prior_x_power = F::from(2);
          for yx_coeff in &mut diff_x.yx_coefficients[0] {
            *yx_coeff *= prior_x_power;
            prior_x_power += F::ONE;
          }
        }
      }

      diff_x
    };

    // Differentation by y is trivial
    // It's the y coefficient as the zero coefficient, and the yx coefficients as the x
    // coefficients
    // This is thanks to any y term over y^2 being reduced out
    let diff_y = Poly {
      y_coefficients: vec![],
      yx_coefficients: vec![],
      x_coefficients: self.yx_coefficients.first().cloned().unwrap_or(vec![]),
      zero_coefficient: self.y_coefficients.first().cloned().unwrap_or(F::ZERO),
    };

    (diff_x, diff_y)
  }

  /// Normalize the x coefficient to 1.
  ///
  /// Panics if there is no x coefficient to normalize or if it cannot be normalized to 1.
  #[must_use]
  pub fn normalize_x_coefficient(self) -> Self {
    let scalar = self.x_coefficients[0].invert().unwrap();
    self * scalar
  }
}
