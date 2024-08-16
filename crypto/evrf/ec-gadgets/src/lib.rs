#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

use ciphersuite::{group::ff::Field, Ciphersuite};

use generalized_bulletproofs_circuit_abstraction::*;

mod dlog;
pub use dlog::*;

/// The specification of a short Weierstrass curve over the field `F`.
///
/// The short Weierstrass curve is defined via the formula `y**2 = x**3 + a*x + b`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CurveSpec<F> {
  /// The `a` constant in the curve formula.
  pub a: F,
  /// The `b` constant in the curve formula.
  pub b: F,
}

/// A struct for a point on a towered curve which has been confirmed to be on-curve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OnCurve {
  pub(crate) x: Variable,
  pub(crate) y: Variable,
}

impl OnCurve {
  /// The variable for the x-coordinate.
  pub fn x(&self) -> Variable {
    self.x
  }
  /// The variable for the y-coordinate.
  pub fn y(&self) -> Variable {
    self.y
  }
}

/// Gadgets for working with points on an elliptic curve defined over the scalar field of the curve
/// of the Bulletproof.
pub trait EcGadgets<C: Ciphersuite> {
  /// Constrain an x and y coordinate as being on the specified curve.
  ///
  /// The specified curve is defined over the scalar field of the curve this proof is performed
  /// over, offering efficient arithmetic.
  ///
  /// May panic if the prover and the point is not actually on-curve.
  fn on_curve(&mut self, curve: &CurveSpec<C::F>, point: (Variable, Variable)) -> OnCurve;

  /// Perform incomplete addition for a fixed point and an on-curve point.
  ///
  /// `a` is the x and y coordinates of the fixed point, assumed to be on-curve.
  ///
  /// `b` is a point prior checked to be on-curve.
  ///
  /// `c` is a point prior checked to be on-curve, constrained to be the sum of `a` and `b`.
  ///
  /// `a` and `b` are checked to have distinct x coordinates.
  ///
  /// This function may panic if `a` is malformed or if the prover and `c` is not actually the sum
  /// of `a` and `b`.
  fn incomplete_add_fixed(&mut self, a: (C::F, C::F), b: OnCurve, c: OnCurve) -> OnCurve;
}

impl<C: Ciphersuite> EcGadgets<C> for Circuit<C> {
  fn on_curve(&mut self, curve: &CurveSpec<C::F>, (x, y): (Variable, Variable)) -> OnCurve {
    let x_eval = self.eval(&LinComb::from(x));
    let (_x, _x_2, x2) =
      self.mul(Some(LinComb::from(x)), Some(LinComb::from(x)), x_eval.map(|x| (x, x)));
    let (_x, _x_2, x3) =
      self.mul(Some(LinComb::from(x2)), Some(LinComb::from(x)), x_eval.map(|x| (x * x, x)));
    let expected_y2 = LinComb::from(x3).term(curve.a, x).constant(curve.b);

    let y_eval = self.eval(&LinComb::from(y));
    let (_y, _y_2, y2) =
      self.mul(Some(LinComb::from(y)), Some(LinComb::from(y)), y_eval.map(|y| (y, y)));

    self.equality(y2.into(), &expected_y2);

    OnCurve { x, y }
  }

  fn incomplete_add_fixed(&mut self, a: (C::F, C::F), b: OnCurve, c: OnCurve) -> OnCurve {
    // Check b.x != a.0
    {
      let bx_lincomb = LinComb::from(b.x);
      let bx_eval = self.eval(&bx_lincomb);
      self.inequality(bx_lincomb, &LinComb::empty().constant(a.0), bx_eval.map(|bx| (bx, a.0)));
    }

    let (x0, y0) = (a.0, a.1);
    let (x1, y1) = (b.x, b.y);
    let (x2, y2) = (c.x, c.y);

    let slope_eval = self.eval(&LinComb::from(x1)).map(|x1| {
      let y1 = self.eval(&LinComb::from(b.y)).unwrap();

      (y1 - y0) * (x1 - x0).invert().unwrap()
    });

    // slope * (x1 - x0) = y1 - y0
    let x1_minus_x0 = LinComb::from(x1).constant(-x0);
    let x1_minus_x0_eval = self.eval(&x1_minus_x0);
    let (slope, _r, o) =
      self.mul(None, Some(x1_minus_x0), slope_eval.map(|slope| (slope, x1_minus_x0_eval.unwrap())));
    self.equality(LinComb::from(o), &LinComb::from(y1).constant(-y0));

    // slope * (x2 - x0) = -y2 - y0
    let x2_minus_x0 = LinComb::from(x2).constant(-x0);
    let x2_minus_x0_eval = self.eval(&x2_minus_x0);
    let (_slope, _x2_minus_x0, o) = self.mul(
      Some(slope.into()),
      Some(x2_minus_x0),
      slope_eval.map(|slope| (slope, x2_minus_x0_eval.unwrap())),
    );
    self.equality(o.into(), &LinComb::empty().term(-C::F::ONE, y2).constant(-y0));

    // slope * slope = x0 + x1 + x2
    let (_slope, _slope_2, o) =
      self.mul(Some(slope.into()), Some(slope.into()), slope_eval.map(|slope| (slope, slope)));
    self.equality(o.into(), &LinComb::from(x1).term(C::F::ONE, x2).constant(x0));

    OnCurve { x: x2, y: y2 }
  }
}
