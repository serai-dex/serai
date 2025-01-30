use ciphersuite::{group::ff::Field, Ciphersuite};

use crate::*;

impl<C: Ciphersuite> Circuit<C> {
  /// Constrain two linear combinations to be equal.
  pub fn equality(&mut self, a: LinComb<C::F>, b: &LinComb<C::F>) {
    self.constrain_equal_to_zero(a - b);
  }

  /// Calculate (and constrain) the inverse of a value.
  ///
  /// A linear combination may optionally be passed as a constraint for the value being inverted.
  /// A reference to the inverted value and its inverse is returned.
  ///
  /// May panic if any linear combinations reference non-existent terms, the witness isn't provided
  /// when proving/is provided when verifying, or if the witness is 0 (and accordingly doesn't have
  /// an inverse).
  pub fn inverse(
    &mut self,
    lincomb: Option<LinComb<C::F>>,
    witness: Option<C::F>,
  ) -> (Variable, Variable) {
    let (l, r, o) = self.mul(lincomb, None, witness.map(|f| (f, f.invert().unwrap())));
    // The output of a value multiplied by its inverse is 1
    // Constrain `1 o - 1 = 0`
    self.constrain_equal_to_zero(LinComb::from(o).constant(-C::F::ONE));
    (l, r)
  }

  /// Constrain two linear combinations as inequal.
  ///
  /// May panic if any linear combinations reference non-existent terms.
  pub fn inequality(&mut self, a: LinComb<C::F>, b: &LinComb<C::F>, witness: Option<(C::F, C::F)>) {
    let l_constraint = a - b;
    // The existence of a multiplicative inverse means a-b != 0, which means a != b
    self.inverse(Some(l_constraint), witness.map(|(a, b)| a - b));
  }
}
