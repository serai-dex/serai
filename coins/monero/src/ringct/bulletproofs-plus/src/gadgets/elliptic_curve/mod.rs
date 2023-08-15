use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;
use ciphersuite::{
  group::{ff::Field, Group},
  Ciphersuite,
};

use ecip::Ecip;

use crate::{
  arithmetic_circuit::{VariableReference, Constraint, Circuit},
  gadgets::assert_non_zero_gadget,
};

mod trinary;
pub use trinary::*;

mod dlog_pok;
pub use dlog_pok::DLogTable;
use dlog_pok::divisor_dlog_pok;

/// An on-curve point which is not identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OnCurvePoint {
  x: VariableReference,
  y: VariableReference,
}

impl OnCurvePoint {
  pub fn x(&self) -> VariableReference {
    self.x
  }
  pub fn y(&self) -> VariableReference {
    self.y
  }
}

fn incomplete_addition<C: Ecip>(
  a: C::G,
  b: C::G,
) -> (C::FieldElement, C::FieldElement, C::FieldElement, C::FieldElement, C::FieldElement) {
  let (x1, y1) = C::to_xy(a);
  let (x2, y2) = C::to_xy(b);

  let c = a + b;

  let (x3, y3) = C::to_xy(c);

  let slope = (y2 - y1) *
    Option::<C::FieldElement>::from((x2 - x1).invert())
      .expect("trying to add perform incomplete addition on points which share an x coordinate");

  let x2m1 = x2 - x1;
  let x3m1 = x3 - x1;

  (x3, y3, slope, x2m1, x3m1)
}

/// Perform operations over the curve embedded into the proof's curve.
pub trait EmbeddedCurveOperations: Ciphersuite {
  type Embedded: Ecip<FieldElement = Self::F>;

  /// Constrains a point to being on curve AND not being the identity.
  fn constrain_on_curve<T: 'static + Transcript>(
    circuit: &mut Circuit<T, Self>,
    x: VariableReference,
    y: VariableReference,
  ) -> OnCurvePoint;

  // Curve Trees, Appendix A.[4, 5]
  // This uses 4 gates theoretically, 5 as implemented here, and 6 constraints
  #[doc(hidden)]
  fn incomplete_add_internal<T: 'static + Transcript>(
    circuit: &mut Circuit<T, Self>,
    p1: OnCurvePoint,
    p2_vars_with_prods: Option<(VariableReference, VariableReference)>,
    p2_consts: Option<(Self::F, Self::F)>,
  ) -> OnCurvePoint {
    debug_assert!(
      p2_vars_with_prods.is_some() ^ p2_consts.is_some(),
      "both p2_vars_with_prods and p2_consts were some, or both were none"
    );

    let OnCurvePoint { x: x1, y: y1 } = p1;

    let (x3, y3, slope, x2m1, x3m1) = if circuit.prover() {
      let x1 = circuit.unchecked_value(x1);
      let y1 = circuit.unchecked_value(y1);
      let a = Self::Embedded::from_xy(x1, y1);

      let (x2, y2) = p2_consts.unwrap_or_else(|| {
        (
          circuit.unchecked_value(p2_vars_with_prods.unwrap().0),
          circuit.unchecked_value(p2_vars_with_prods.unwrap().1),
        )
      });
      let b = Self::Embedded::from_xy(x2, y2);

      let (x3, y3, slope, x2m1, x3m1) = incomplete_addition::<Self::Embedded>(a, b);

      (Some(x3), Some(y3), Some(slope), Some(x2m1), Some(x3m1))
    } else {
      (None, None, None, None, None)
    };

    let x3 = circuit.add_secret_input(x3);
    let y3 = circuit.add_secret_input(y3);
    let slope = circuit.add_secret_input(slope);
    let x2m1 = circuit.add_secret_input(x2m1);
    let x3m1 = circuit.add_secret_input(x3m1);

    let x1 = circuit.variable_to_product(x1).expect(
      "x1 wasn't prior used in a product statement. this shouldn't be possible if on-curve checked",
    );
    let y1 = circuit.variable_to_product(y1).expect(
      "y1 wasn't prior used in a product statement. this shouldn't be possible if on-curve checked",
    );

    let x2 = p2_vars_with_prods.map(|(x, _)| circuit.variable_to_product(x).unwrap());
    let y2 = p2_vars_with_prods.map(|(_, y)| circuit.variable_to_product(y).unwrap());

    // Prove x2m1 is non-zero, meaning x2 != x1, enabling incomplete formulas
    assert_non_zero_gadget(circuit, x2m1);

    // Constrain x2m1 is correct
    let mut constraint = Constraint::new("x2m1");
    if let Some(x2) = x2 {
      constraint.weight(x2, Self::F::ONE);
    } else {
      // -x1 + -(x2 - x1)
      // -x1 - x2 + x1
      // -x2
      constraint.rhs_offset(-p2_consts.unwrap().0);
    }
    constraint.weight(x1, -Self::F::ONE);
    // Safe since the non-zero gadget will use it in a product statement
    constraint.weight(circuit.variable_to_product(x2m1).unwrap(), -Self::F::ONE);
    circuit.constrain(constraint);

    // A.4 (6)
    {
      let ((_, _, slope_x2m1), _) = circuit.product(slope, x2m1);
      // slope_x2m1 - (y2 - y1) == 0
      let mut constraint = Constraint::new("slope_x2m1");
      constraint.weight(slope_x2m1, Self::F::ONE);
      if let Some(y2) = y2 {
        constraint.weight(y2, -Self::F::ONE);
      } else {
        constraint.rhs_offset(p2_consts.unwrap().1);
      }
      constraint.weight(y1, Self::F::ONE);
      circuit.constrain(constraint);
    }

    // Use x3/y3 in a product statement so they can be used in constraints
    // TODO: Design around this internally
    let ((x3_prod, y3_prod, _), _) = circuit.product(x3, y3);

    // A.4 (7)
    {
      let ((_, x3m1, slope_x3m1), _) = circuit.product(slope, x3m1);

      // Constrain x3m1's accuracy
      {
        let mut constraint = Constraint::new("x3m1");
        constraint.weight(x3_prod, Self::F::ONE);
        constraint.weight(x1, -Self::F::ONE);
        constraint.weight(x3m1, -Self::F::ONE);
        circuit.constrain(constraint);
      }

      // slope_x3m1 - (-y3 - y1) == 0
      let mut constraint = Constraint::new("slope_x3m1");
      constraint.weight(slope_x3m1, Self::F::ONE);
      constraint.weight(y3_prod, Self::F::ONE);
      constraint.weight(y1, Self::F::ONE);
      circuit.constrain(constraint);
    }

    // A.4 (8)
    {
      let ((_, _, slope_squared), _) = circuit.product(slope, slope);

      // 0 == x1 + x2 + x3 - slope_squared
      let mut constraint = Constraint::new("slope_squared");
      constraint.weight(slope_squared, -Self::F::ONE);
      constraint.weight(x3_prod, Self::F::ONE);
      constraint.weight(x1, Self::F::ONE);
      if let Some(x2) = x2 {
        constraint.weight(x2, Self::F::ONE);
      } else {
        constraint.rhs_offset(-p2_consts.unwrap().0);
      }
      circuit.constrain(constraint);
    }

    OnCurvePoint { x: x3, y: y3 }
  }

  /// Performs addition between two points, where P1 != P2, P1 != -P2, and neither P1 nor P2 are
  /// identity.
  ///
  /// The only checks performed by this function are P1 != P2 and P1 != -P2. Neither point is
  /// checked to not be identity.
  fn incomplete_add<T: 'static + Transcript>(
    circuit: &mut Circuit<T, Self>,
    p1: OnCurvePoint,
    p2: OnCurvePoint,
  ) -> OnCurvePoint {
    Self::incomplete_add_internal(circuit, p1, Some((p2.x, p2.y)), None)
  }

  /// Performs addition between two points, where P1 != P2, P1 != -P2, and neither P1 nor P2 are
  /// identity.
  ///
  /// The only checks performed by this function are P1 != P2, P1 != -P2, and P2 != identity. P1
  /// is not checked to not be identity.
  ///
  /// This uses the same function internally as incomplete_add and accordingly isn't more
  /// performant. Its advantage is in avoiding the neccessity of constraining a point to be on
  /// curve.
  fn incomplete_add_constant<T: 'static + Transcript>(
    circuit: &mut Circuit<T, Self>,
    p1: OnCurvePoint,
    p2: <Self::Embedded as Ciphersuite>::G,
  ) -> OnCurvePoint {
    debug_assert!(
      !bool::from(p2.is_identity()),
      "instructed to perform incomplete addition with identity"
    );
    Self::incomplete_add_internal(circuit, p1, None, Some(Self::Embedded::to_xy(p2)))
  }

  // This uses a divisor to prove knowledge of a DLog with just 1.75 gates per point, plus a
  // constant 2 gates
  // This is more than twice as performant as incomplete addition and is closer to being complete
  // (only identity is unsupported)
  //
  // Ideally, it's 1.5 gates per point, plus a constant 3 (if an O(1) divisor-non-zero check is
  // implemented)
  //
  // TODO: The currently implemented vector commitment scheme, if used, multiplies the gate count
  // by 7 due to adding 2 gates per item (with 3 items per gate (left, right, output))
  // That means this uses 12.25 gates per point
  // If a zero-cost vector commitment scheme isn't implemented, this isn't worth it for proofs
  // which don't already incur the vector commitment scheme's overhead
  //
  // Gate count is notated GC

  // TODO: Can we impl a batch DLog PoK?
  fn dlog_pok<R: RngCore + CryptoRng, T: 'static + Transcript>(
    rng: &mut R,
    circuit: &mut Circuit<T, Self>,
    G: &'static DLogTable<Self::Embedded>,
    p: OnCurvePoint,
    dlog: Option<<Self::Embedded as Ciphersuite>::F>,
  ) {
    divisor_dlog_pok(rng, circuit, G, p, dlog)
  }
}

pub trait EmbeddedShortWeierstrass: Ciphersuite {
  type Embedded: Ecip<FieldElement = Self::F>;

  const B: u64;
}

impl<C: EmbeddedShortWeierstrass> EmbeddedCurveOperations for C {
  type Embedded = <C as EmbeddedShortWeierstrass>::Embedded;

  // y**2 = x**3 + B
  fn constrain_on_curve<T: 'static + Transcript>(
    circuit: &mut Circuit<T, Self>,
    x: VariableReference,
    y: VariableReference,
  ) -> OnCurvePoint {
    let ((_, _, y2_prod), _) = circuit.product(y, y);
    let (_, x2) = circuit.product(x, x);
    let ((_, _, x3), _) = circuit.product(x2, x);

    let mut constraint = Constraint::new("on-curve");
    constraint.weight(y2_prod, Self::F::ONE);
    constraint.weight(x3, -Self::F::ONE);
    constraint.rhs_offset(Self::F::from(Self::B));
    circuit.constrain(constraint);

    OnCurvePoint { x, y }
  }
}
