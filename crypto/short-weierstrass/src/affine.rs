use core::ops::*;

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable, ConditionallyNegatable};
use zeroize::DefaultIsZeroes;

use rand_core::RngCore;

use group::ff::{Field as _, PrimeField as _};

use crate::{ShortWeierstrass, Projective};

/// A point represented with affine coordinates.
#[derive(Debug)]
pub struct Affine<C: ShortWeierstrass> {
  pub(crate) x: C::FieldElement,
  pub(crate) y: C::FieldElement,
}
impl<C: ShortWeierstrass> Clone for Affine<C> {
  fn clone(&self) -> Self {
    *self
  }
}
impl<C: ShortWeierstrass> Copy for Affine<C> {}

impl<C: ShortWeierstrass> Affine<C> {
  pub fn try_from(projective: &Projective<C>) -> CtOption<Self> {
    let z_inv = projective.z.invert().unwrap_or(C::FieldElement::ZERO);
    let if_non_identity = Self { x: projective.x * z_inv, y: projective.y * z_inv };
    let identity = z_inv.ct_eq(&C::FieldElement::ZERO);
    // If this isn't a valid affine point, switch to a valid affine point
    let value = <_>::conditional_select(&if_non_identity, &C::GENERATOR, identity);
    // This is valid if the projective point wasn't the identity
    CtOption::new(value, !identity)
  }
}

impl<C: ShortWeierstrass> Default for Affine<C> {
  fn default() -> Self {
    C::GENERATOR
  }
}
impl<C: ShortWeierstrass> DefaultIsZeroes for Affine<C> {}

impl<C: ShortWeierstrass> ConstantTimeEq for Affine<C> {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
  }
}
impl<C: ShortWeierstrass> PartialEq for Affine<C> {
  fn eq(&self, other: &Self) -> bool {
    self.ct_eq(other).into()
  }
}
impl<C: ShortWeierstrass> Eq for Affine<C> {}

impl<C: ShortWeierstrass> ConditionallySelectable for Affine<C> {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    let x = C::FieldElement::conditional_select(&a.x, &b.x, choice);
    let y = C::FieldElement::conditional_select(&a.y, &b.y, choice);
    Affine { x, y }
  }
}

impl<C: ShortWeierstrass> Neg for Affine<C> {
  type Output = Self;
  fn neg(mut self) -> Self::Output {
    self.y = -self.y;
    self
  }
}

impl<C: ShortWeierstrass> ConditionallyNegatable for Affine<C> {
  fn conditional_negate(&mut self, negate: Choice) {
    self.y = <_>::conditional_select(&self.y, &-self.y, negate);
  }
}

impl<C: ShortWeierstrass> Affine<C> {
  /// Create an affine point from `x, y` coordinates, without performing any checks.
  ///
  /// This should NOT be used. It is solely intended for trusted data at compile-time. It MUST NOT
  /// be used with any untrusted/unvalidated data. Providing any point not within the largest
  /// prime-order subgroup has completely undefined behavior.
  pub const fn from_xy_unchecked(x: C::FieldElement, y: C::FieldElement) -> Self {
    Self { x, y }
  }

  /// Decompress a point from it's `x`-coordinate and the sign of the `y` coordinate.
  pub fn decompress(x: C::FieldElement, odd_y: Choice) -> CtOption<Self> {
    let y_square = ((x.square() + C::A) * x) + C::B;
    y_square.sqrt().and_then(|mut y| {
      y = <_>::conditional_select(&y, &-y, y.is_odd().ct_ne(&odd_y));
      // Handles the exceptional case of `y = 0, odd_y = 1`
      CtOption::new(Self { x, y }, y.is_odd().ct_eq(&odd_y))
    })
  }

  /// The `x, y` coordinates of this point.
  pub fn coordinates(self) -> (C::FieldElement, C::FieldElement) {
    (self.x, self.y)
  }

  /// Sample a random on-curve point with an unknown discrete logarithm w.r.t. any other points.
  ///
  /// This runs in time variable to the amount of samples required to find a point.
  pub fn random(mut rng: impl RngCore) -> Self {
    loop {
      let x = C::FieldElement::random(&mut rng);
      #[expect(clippy::as_conversions)]
      let y_is_odd = Choice::from((rng.next_u64() % 2) as u8);
      let Some(res) = Option::<Self>::from(Self::decompress(x, y_is_odd)) else { continue };
      return res;
    }
  }
}
