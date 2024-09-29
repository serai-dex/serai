#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

use group::{
  ff::{Field, PrimeField, PrimeFieldBits},
  Group,
};

mod poly;
pub use poly::Poly;

#[cfg(test)]
mod tests;

/// A curve usable with this library.
pub trait DivisorCurve: Group + ConstantTimeEq + ConditionallySelectable {
  /// An element of the field this curve is defined over.
  type FieldElement: Zeroize + PrimeField + ConditionallySelectable;

  /// The A in the curve equation y^2 = x^3 + A x + B.
  fn a() -> Self::FieldElement;
  /// The B in the curve equation y^2 = x^3 + A x + B.
  fn b() -> Self::FieldElement;

  /// y^2 - x^3 - A x - B
  ///
  /// Section 2 of the security proofs define this modulus.
  ///
  /// This MUST NOT be overriden.
  // TODO: Move to an extension trait
  fn divisor_modulus() -> Poly<Self::FieldElement> {
    Poly {
      // 0 y**1, 1 y*2
      y_coefficients: vec![Self::FieldElement::ZERO, Self::FieldElement::ONE],
      yx_coefficients: vec![],
      x_coefficients: vec![
        // - A x
        -Self::a(),
        // 0 x^2
        Self::FieldElement::ZERO,
        // - x^3
        -Self::FieldElement::ONE,
      ],
      // - B
      zero_coefficient: -Self::b(),
    }
  }

  /// Convert a point to its x and y coordinates.
  ///
  /// Returns None if passed the point at infinity.
  fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)>;
}

/// Calculate the slope and intercept between two points.
///
/// This function panics when `a @ infinity`, `b @ infinity`, `a == b`, or when `a == -b`.
pub(crate) fn slope_intercept<C: DivisorCurve>(a: C, b: C) -> (C::FieldElement, C::FieldElement) {
  let (ax, ay) = C::to_xy(a).unwrap();
  debug_assert_eq!(C::divisor_modulus().eval(ax, ay), C::FieldElement::ZERO);
  let (bx, by) = C::to_xy(b).unwrap();
  debug_assert_eq!(C::divisor_modulus().eval(bx, by), C::FieldElement::ZERO);
  let slope = (by - ay) *
    Option::<C::FieldElement>::from((bx - ax).invert())
      .expect("trying to get slope/intercept of points sharing an x coordinate");
  let intercept = by - (slope * bx);
  debug_assert!(bool::from((ay - (slope * ax) - intercept).is_zero()));
  debug_assert!(bool::from((by - (slope * bx) - intercept).is_zero()));
  (slope, intercept)
}

// The line interpolating two points.
fn line<C: DivisorCurve>(a: C, b: C) -> Poly<C::FieldElement> {
  #[derive(Clone, Copy)]
  struct LinesRes<F: ConditionallySelectable> {
    y_coefficient: F,
    x_coefficient: F,
    zero_coefficient: F,
  }
  impl<F: ConditionallySelectable> ConditionallySelectable for LinesRes<F> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
      Self {
        y_coefficient: <_>::conditional_select(&a.y_coefficient, &b.y_coefficient, choice),
        x_coefficient: <_>::conditional_select(&a.x_coefficient, &b.x_coefficient, choice),
        zero_coefficient: <_>::conditional_select(&a.zero_coefficient, &b.zero_coefficient, choice),
      }
    }
  }

  let a_is_identity = a.is_identity();
  let b_is_identity = b.is_identity();

  // If they're both the point at infinity, we simply set the line to one
  let both_are_identity = a_is_identity & b_is_identity;
  let if_both_are_identity = LinesRes {
    y_coefficient: C::FieldElement::ZERO,
    x_coefficient: C::FieldElement::ZERO,
    zero_coefficient: C::FieldElement::ONE,
  };

  // If either point is the point at infinity, or these are additive inverses, the line is
  // `1 * x - x`. The first `x` is a term in the polynomial, the `x` is the `x` coordinate of these
  // points (of which there is one, as the second point is either at infinity or has a matching `x`
  // coordinate).
  let one_is_identity = a_is_identity | b_is_identity;
  let additive_inverses = a.ct_eq(&-b);
  let one_is_identity_or_additive_inverses = one_is_identity | additive_inverses;
  let if_one_is_identity_or_additive_inverses = {
    // If both are identity, set `a` to the generator so we can safely evaluate the following
    // (which we won't select at the end of this function)
    let a = <_>::conditional_select(&a, &C::generator(), both_are_identity);
    // If `a` is identity, this selects `b`. If `a` isn't identity, this selects `a`
    let non_identity = <_>::conditional_select(&a, &b, a.is_identity());
    let (x, _) = C::to_xy(non_identity).unwrap();
    LinesRes {
      y_coefficient: C::FieldElement::ZERO,
      x_coefficient: C::FieldElement::ONE,
      zero_coefficient: -x,
    }
  };

  // The following calculation assumes neither point is the point at infinity
  // If either are, we use a prior result
  // To ensure we can calculcate a result here, set any points at infinity to the generator
  let a = <_>::conditional_select(&a, &C::generator(), a_is_identity);
  let b = <_>::conditional_select(&b, &C::generator(), b_is_identity);
  // It also assumes a, b aren't additive inverses which is also covered by a prior result
  let b = <_>::conditional_select(&b, &a.double(), additive_inverses);

  // If the points are equal, we use the line interpolating the sum of these points with the point
  // at infinity
  let b = <_>::conditional_select(&b, &-a.double(), a.ct_eq(&b));

  let (slope, intercept) = slope_intercept::<C>(a, b);

  // Section 4 of the proofs explicitly state the line `L = y - lambda * x - mu`
  // y - (slope * x) - intercept
  let mut res = LinesRes {
    y_coefficient: C::FieldElement::ONE,
    x_coefficient: -slope,
    zero_coefficient: -intercept,
  };

  res = <_>::conditional_select(
    &res,
    &if_one_is_identity_or_additive_inverses,
    one_is_identity_or_additive_inverses,
  );
  res = <_>::conditional_select(&res, &if_both_are_identity, both_are_identity);

  Poly {
    y_coefficients: vec![res.y_coefficient],
    yx_coefficients: vec![],
    x_coefficients: vec![res.x_coefficient],
    zero_coefficient: res.zero_coefficient,
  }
}

/// Create a divisor interpolating the following points.
///
/// Returns None if:
///   - No points were passed in
///   - The points don't sum to the point at infinity
///   - A passed in point was the point at infinity
///
/// If the arguments were valid, this function executes in an amount of time constant to the amount
/// of points.
#[allow(clippy::new_ret_no_self)]
pub fn new_divisor<C: DivisorCurve>(points: &[C]) -> Option<Poly<C::FieldElement>> {
  // No points were passed in, this is the point at infinity, or the single point isn't infinity
  // and accordingly doesn't sum to infinity. All three cause us to return None
  // Checks a bit other than the first bit is set, meaning this is >= 2
  let mut invalid_args = (points.len() & (!1)).ct_eq(&0);
  // The points don't sum to the point at infinity
  invalid_args |= !points.iter().sum::<C>().is_identity();
  // A point was the point at identity
  for point in points {
    invalid_args |= point.is_identity();
  }
  if bool::from(invalid_args) {
    None?;
  }

  let points_len = points.len();

  // Create the initial set of divisors
  let mut divs = vec![];
  let mut iter = points.iter().copied();
  while let Some(a) = iter.next() {
    let b = iter.next();

    // Draw the line between those points
    // These unwraps are branching on the length of the iterator, not violating the constant-time
    // priorites desired
    divs.push((2, a + b.unwrap_or(C::identity()), line::<C>(a, b.unwrap_or(-a))));
  }

  let modulus = C::divisor_modulus();

  // Our Poly algorithm is leaky and will create an excessive amount of y x**j and x**j
  // coefficients which are zero, yet as our implementation is constant time, still come with
  // an immense performance cost. This code truncates the coefficients we know are zero.
  let trim = |divisor: &mut Poly<_>, points_len: usize| {
    // We should only be trimming divisors reduced by the modulus
    debug_assert!(divisor.yx_coefficients.len() <= 1);
    if divisor.yx_coefficients.len() == 1 {
      let truncate_to = ((points_len + 1) / 2).saturating_sub(2);
      #[cfg(debug_assertions)]
      for p in truncate_to .. divisor.yx_coefficients[0].len() {
        debug_assert_eq!(divisor.yx_coefficients[0][p], <C::FieldElement as Field>::ZERO);
      }
      divisor.yx_coefficients[0].truncate(truncate_to);
    }
    {
      let truncate_to = points_len / 2;
      #[cfg(debug_assertions)]
      for p in truncate_to .. divisor.x_coefficients.len() {
        debug_assert_eq!(divisor.x_coefficients[p], <C::FieldElement as Field>::ZERO);
      }
      divisor.x_coefficients.truncate(truncate_to);
    }
  };

  // Pair them off until only one remains
  while divs.len() > 1 {
    let mut next_divs = vec![];
    // If there's an odd amount of divisors, carry the odd one out to the next iteration
    if (divs.len() % 2) == 1 {
      next_divs.push(divs.pop().unwrap());
    }

    while let Some((a_points, a, a_div)) = divs.pop() {
      let (b_points, b, b_div) = divs.pop().unwrap();
      let points = a_points + b_points;

      // Merge the two divisors
      let numerator = a_div.mul_mod(&b_div, &modulus).mul_mod(&line::<C>(a, b), &modulus);
      let denominator = line::<C>(a, -a).mul_mod(&line::<C>(b, -b), &modulus);
      let (mut q, r) = numerator.div_rem(&denominator);
      debug_assert_eq!(r, Poly::zero());

      trim(&mut q, 1 + points);

      next_divs.push((points, a + b, q));
    }

    divs = next_divs;
  }

  // Return the unified divisor
  let mut divisor = divs.remove(0).2;
  trim(&mut divisor, points_len);
  Some(divisor)
}

/// The decomposition of a scalar.
///
/// The decomposition ($d$) of a scalar ($s$) has the following two properties:
///
/// - $\sum^{\mathsf{NUM_BITS} - 1}_{i=0} d_i * 2^i = s$
/// - $\sum^{\mathsf{NUM_BITS} - 1}_{i=0} d_i = \mathsf{NUM_BITS}$
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ScalarDecomposition<F: Zeroize + PrimeFieldBits> {
  scalar: F,
  decomposition: Vec<u64>,
}

impl<F: Zeroize + PrimeFieldBits> ScalarDecomposition<F> {
  /// Decompose a scalar.
  pub fn new(scalar: F) -> Self {
    /*
      We need the sum of the coefficients to equal F::NUM_BITS. The scalar's bits will be less than
      F::NUM_BITS. Accordingly, we need to increment the sum of the coefficients without
      incrementing the scalar represented. We do this by finding the highest non-0 coefficient,
      decrementing it, and increasing the immediately less significant coefficient by 2. This
      increases the sum of the coefficients by 1 (-1+2=1).
    */

    let num_bits = u64::from(F::NUM_BITS);

    // Obtain the bits of the scalar
    let num_bits_usize = usize::try_from(num_bits).unwrap();
    let mut decomposition = vec![0; num_bits_usize];
    for (i, bit) in scalar.to_le_bits().into_iter().take(num_bits_usize).enumerate() {
      let bit = u64::from(u8::from(bit));
      decomposition[i] = bit;
    }

    // The following algorithm only works if the value of the scalar exceeds num_bits
    // If it isn't, we increase it by the modulus such that it does exceed num_bits
    {
      let mut less_than_num_bits = Choice::from(0);
      for i in 0 .. num_bits {
        less_than_num_bits |= scalar.ct_eq(&F::from(i));
      }
      let mut decomposition_of_modulus = vec![0; num_bits_usize];
      // Decompose negative one
      for (i, bit) in (-F::ONE).to_le_bits().into_iter().take(num_bits_usize).enumerate() {
        let bit = u64::from(u8::from(bit));
        decomposition_of_modulus[i] = bit;
      }
      // Increment it by one
      decomposition_of_modulus[0] += 1;

      // Add the decomposition onto the decomposition of the modulus
      for i in 0 .. num_bits_usize {
        let new_decomposition = <_>::conditional_select(
          &decomposition[i],
          &(decomposition[i] + decomposition_of_modulus[i]),
          less_than_num_bits,
        );
        decomposition[i] = new_decomposition;
      }
    }

    // Calculcate the sum of the coefficients
    let mut sum_of_coefficients: u64 = 0;
    for decomposition in &decomposition {
      sum_of_coefficients += *decomposition;
    }

    /*
      Now, because we added a log2(k)-bit number to a k-bit number, we may have our sum of
      coefficients be *too high*. We attempt to reduce the sum of the coefficients accordingly.

      This algorithm is guaranteed to complete as expected. Take the sequence `222`. `222` becomes
      `032` becomes `013`. Even if the next coefficient in the sequence is `2`, the third
      coefficient will be reduced once and the next coefficient (`2`, increased to `3`) will only
      be eligible for reduction once. This demonstrates, even for a worst case of log2(k) `2`s
      followed by `1`s (as possible if the modulus is a Mersenne prime), the log2(k) `2`s can be
      reduced as necessary so long as there is a single coefficient after (requiring the entire
      sequence be at least of length log2(k) + 1). For a 2-bit number, log2(k) + 1 == 2, so this
      holds for any odd prime field.

      To fully type out the demonstration for the Mersenne prime 3, with scalar to encode 1 (the
      highest value less than the number of bits):

      10 - Little-endian bits of 1
      21 - Little-endian bits of 1, plus the modulus
      02 - After one reduction, where the sum of the coefficients does in fact equal 2 (the target)
    */
    {
      let mut log2_num_bits = 0;
      while (1 << log2_num_bits) < num_bits {
        log2_num_bits += 1;
      }

      for _ in 0 .. log2_num_bits {
        // If the sum of coefficients is the amount of bits, we're done
        let mut done = sum_of_coefficients.ct_eq(&num_bits);

        for i in 0 .. (num_bits_usize - 1) {
          let should_act = (!done) & decomposition[i].ct_gt(&1);
          // Subtract 2 from this coefficient
          let amount_to_sub = <_>::conditional_select(&0, &2, should_act);
          decomposition[i] -= amount_to_sub;
          // Add 1 to the next coefficient
          let amount_to_add = <_>::conditional_select(&0, &1, should_act);
          decomposition[i + 1] += amount_to_add;

          // Also update the sum of coefficients
          sum_of_coefficients -= <_>::conditional_select(&0, &1, should_act);

          // If we updated the coefficients this loop iter, we're done for this loop iter
          done |= should_act;
        }
      }
    }

    for _ in 0 .. num_bits {
      // If the sum of coefficients is the amount of bits, we're done
      let mut done = sum_of_coefficients.ct_eq(&num_bits);

      // Find the highest coefficient currently non-zero
      for i in (1 .. decomposition.len()).rev() {
        // If this is non-zero, we should decrement this coefficient if we haven't already
        // decremented a coefficient this round
        let is_non_zero = !(0.ct_eq(&decomposition[i]));
        let should_act = (!done) & is_non_zero;

        // Update this coefficient and the prior coefficient
        let amount_to_sub = <_>::conditional_select(&0, &1, should_act);
        decomposition[i] -= amount_to_sub;

        let amount_to_add = <_>::conditional_select(&0, &2, should_act);
        // i must be at least 1, so i - 1 will be at least 0 (meaning it's safe to index with)
        decomposition[i - 1] += amount_to_add;

        // Also update the sum of coefficients
        sum_of_coefficients += <_>::conditional_select(&0, &1, should_act);

        // If we updated the coefficients this loop iter, we're done for this loop iter
        done |= should_act;
      }
    }
    debug_assert!(bool::from(decomposition.iter().sum::<u64>().ct_eq(&num_bits)));

    ScalarDecomposition { scalar, decomposition }
  }

  /// The decomposition of the scalar.
  pub fn decomposition(&self) -> &[u64] {
    &self.decomposition
  }

  /// A divisor to prove a scalar multiplication.
  ///
  /// The divisor will interpolate $-(s \cdot G)$ with $d_i$ instances of $2^i \cdot G$.
  ///
  /// This function executes in constant time with regards to the scalar.
  ///
  /// This function MAY panic if this scalar is zero.
  pub fn scalar_mul_divisor<C: Zeroize + DivisorCurve<Scalar = F>>(
    &self,
    mut generator: C,
  ) -> Poly<C::FieldElement> {
    // 1 is used for the resulting point, NUM_BITS is used for the decomposition, and then we store
    // one additional index in a usize for the points we shouldn't write at all (hence the +2)
    let _ = usize::try_from(<C::Scalar as PrimeField>::NUM_BITS + 2)
      .expect("NUM_BITS + 2 didn't fit in usize");
    let mut divisor_points =
      vec![C::identity(); (<C::Scalar as PrimeField>::NUM_BITS + 1) as usize];

    // Write the inverse of the resulting point
    divisor_points[0] = -generator * self.scalar;

    // Write the decomposition
    let mut write_to: u32 = 1;
    for coefficient in &self.decomposition {
      let mut coefficient = *coefficient;
      // Iterate over the maximum amount of iters for this value to be constant time regardless of
      // any branch prediction algorithms
      for _ in 0 .. <C::Scalar as PrimeField>::NUM_BITS {
        // Write the generator to the slot we're supposed to
        /*
          Without this loop, we'd increment this dependent on the distribution within the
          decomposition. If the distribution is bottom-heavy, we won't access the tail of
          `divisor_points` for a while, risking it being ejected out of the cache (causing a cache
          miss which may not occur with a top-heavy distribution which quickly moves to the tail).

          This is O(log2(NUM_BITS) ** 3) though, as this the third loop, which is horrific.
        */
        for i in 1 ..= <C::Scalar as PrimeField>::NUM_BITS {
          divisor_points[i as usize] =
            <_>::conditional_select(&divisor_points[i as usize], &generator, i.ct_eq(&write_to));
        }
        // If the coefficient isn't zero, increment write_to (so we don't overwrite this generator
        // when it should be there)
        let coefficient_not_zero = !coefficient.ct_eq(&0);
        write_to = <_>::conditional_select(&write_to, &(write_to + 1), coefficient_not_zero);
        // Subtract one from the coefficient, if it's not zero and won't underflow
        coefficient =
          <_>::conditional_select(&coefficient, &coefficient.wrapping_sub(1), coefficient_not_zero);
      }
      generator = generator.double();
    }

    // Create a divisor out of all points except the last point which is solely scratch
    let res = new_divisor(&divisor_points).unwrap();
    divisor_points.zeroize();
    res
  }
}

#[cfg(any(test, feature = "pasta"))]
mod pasta {
  use group::{ff::Field, Curve};
  use pasta_curves::{
    arithmetic::{Coordinates, CurveAffine},
    Ep, Fp, Eq, Fq,
  };
  use crate::DivisorCurve;

  impl DivisorCurve for Ep {
    type FieldElement = Fp;

    fn a() -> Self::FieldElement {
      Self::FieldElement::ZERO
    }
    fn b() -> Self::FieldElement {
      Self::FieldElement::from(5u64)
    }

    fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)> {
      Option::<Coordinates<_>>::from(point.to_affine().coordinates())
        .map(|coords| (*coords.x(), *coords.y()))
    }
  }

  impl DivisorCurve for Eq {
    type FieldElement = Fq;

    fn a() -> Self::FieldElement {
      Self::FieldElement::ZERO
    }
    fn b() -> Self::FieldElement {
      Self::FieldElement::from(5u64)
    }

    fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)> {
      Option::<Coordinates<_>>::from(point.to_affine().coordinates())
        .map(|coords| (*coords.x(), *coords.y()))
    }
  }
}

#[cfg(any(test, feature = "ed25519"))]
mod ed25519 {
  use group::{
    ff::{Field, PrimeField},
    Group, GroupEncoding,
  };
  use dalek_ff_group::{FieldElement, EdwardsPoint};

  impl crate::DivisorCurve for EdwardsPoint {
    type FieldElement = FieldElement;

    // Wei25519 a/b
    // https://www.ietf.org/archive/id/draft-ietf-lwig-curve-representations-02.pdf E.3
    fn a() -> Self::FieldElement {
      let mut be_bytes =
        hex::decode("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144").unwrap();
      be_bytes.reverse();
      let le_bytes = be_bytes;
      Self::FieldElement::from_repr(le_bytes.try_into().unwrap()).unwrap()
    }
    fn b() -> Self::FieldElement {
      let mut be_bytes =
        hex::decode("7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864").unwrap();
      be_bytes.reverse();
      let le_bytes = be_bytes;

      Self::FieldElement::from_repr(le_bytes.try_into().unwrap()).unwrap()
    }

    // https://www.ietf.org/archive/id/draft-ietf-lwig-curve-representations-02.pdf E.2
    fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)> {
      if bool::from(point.is_identity()) {
        None?;
      }

      // Extract the y coordinate from the compressed point
      let mut edwards_y = point.to_bytes();
      let x_is_odd = edwards_y[31] >> 7;
      edwards_y[31] &= (1 << 7) - 1;
      let edwards_y = Self::FieldElement::from_repr(edwards_y).unwrap();

      // Recover the x coordinate
      let edwards_y_sq = edwards_y * edwards_y;
      let D = -Self::FieldElement::from(121665u64) *
        Self::FieldElement::from(121666u64).invert().unwrap();
      let mut edwards_x = ((edwards_y_sq - Self::FieldElement::ONE) *
        ((D * edwards_y_sq) + Self::FieldElement::ONE).invert().unwrap())
      .sqrt()
      .unwrap();
      if u8::from(bool::from(edwards_x.is_odd())) != x_is_odd {
        edwards_x = -edwards_x;
      }

      // Calculate the x and y coordinates for Wei25519
      let edwards_y_plus_one = Self::FieldElement::ONE + edwards_y;
      let one_minus_edwards_y = Self::FieldElement::ONE - edwards_y;
      let wei_x = (edwards_y_plus_one * one_minus_edwards_y.invert().unwrap()) +
        (Self::FieldElement::from(486662u64) * Self::FieldElement::from(3u64).invert().unwrap());
      let c =
        (-(Self::FieldElement::from(486662u64) + Self::FieldElement::from(2u64))).sqrt().unwrap();
      let wei_y = c * edwards_y_plus_one * (one_minus_edwards_y * edwards_x).invert().unwrap();
      Some((wei_x, wei_y))
    }
  }
}
