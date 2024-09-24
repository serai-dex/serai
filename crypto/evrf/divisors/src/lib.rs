#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

use group::{
  ff::{Field, PrimeField},
  Group,
};

mod poly;
pub use poly::*;

#[cfg(test)]
mod tests;

/// A curve usable with this library.
pub trait DivisorCurve: Group + ConstantTimeEq + ConditionallySelectable {
  /// An element of the field this curve is defined over.
  type FieldElement: PrimeField + ConditionallySelectable;

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

  res = <_>::conditional_select(&res, &if_both_are_identity, both_are_identity);
  res = <_>::conditional_select(
    &res,
    &if_one_is_identity_or_additive_inverses,
    one_is_identity_or_additive_inverses,
  );

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

  // Create the initial set of divisors
  let mut divs = vec![];
  let mut iter = points.iter().copied();
  while let Some(a) = iter.next() {
    let b = iter.next();

    // Draw the line between those points
    // These unwraps are branching on the length of the iterator, not violating the constant-time
    // priorites desired
    divs.push((a + b.unwrap_or(C::identity()), line::<C>(a, b.unwrap_or(-a))));
  }

  let modulus = C::divisor_modulus();

  // Pair them off until only one remains
  while divs.len() > 1 {
    let mut next_divs = vec![];
    // If there's an odd amount of divisors, carry the odd one out to the next iteration
    if (divs.len() % 2) == 1 {
      next_divs.push(divs.pop().unwrap());
    }

    while let Some((a, a_div)) = divs.pop() {
      let (b, b_div) = divs.pop().unwrap();

      // Merge the two divisors
      let numerator = a_div.mul_mod(&b_div, &modulus).mul_mod(&line::<C>(a, b), &modulus);
      let denominator = line::<C>(a, -a).mul_mod(&line::<C>(b, -b), &modulus);
      let (q, r) = numerator.clone().div_rem(&denominator);
      // Checks all coefficients within the remainder are 0
      // This is presumed imperfect yet is expected as a sanity check, not a strict soundness bound
      debug_assert_eq!(r.eval(C::FieldElement::ONE, C::FieldElement::ONE), C::FieldElement::ZERO);
      debug_assert_eq!(r.eval(C::FieldElement::ONE, -C::FieldElement::ONE), C::FieldElement::ZERO);

      next_divs.push((a + b, q));
    }

    divs = next_divs;
  }

  // Return the unified divisor
  Some(divs.remove(0).1)
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
