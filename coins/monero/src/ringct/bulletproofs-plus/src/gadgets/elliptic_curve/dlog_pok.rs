use std::collections::VecDeque;

use rand_core::{RngCore, CryptoRng};

use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

use transcript::Transcript;
use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    Group,
  },
  Ciphersuite,
};

use ecip::{Ecip, Poly, Divisor};

use crate::{
  arithmetic_circuit::{ProductReference, ChallengeReference, Constraint, Circuit},
  gadgets::{Bit, elliptic_curve::*},
};

/// A table for efficient proofs of knowledge of discrete logarithms over a specified generator.

/*
  Creating a bit takes one gate. Selecting a zero-knowledge variable takes one gate.

  The current DLog PoK takes in 255 bits (each costing 1 gate to be created each) and performs
  addition for 255 points, each addition costing 1.75 gates. This means without tabling, the DLog
  PoK costs 255 + (255 * 1.75) = 701.25 gates.

  If we created 3-wide tables, we'd need 2 bits to perform the selection (1 bit for 0 or 1, 1 bit
  for the result of the prior operation or 2). This not only adds a gate to create the second bit,
  yet also one for the second selection (which is ZK or constant). This would be (2 * 255) +
  (161 * 1.75) = 791.75 gates.

  If we used a 3-set membership, it would only take n - 1 gates, AKA 2 gates. This would be
  ((3 - 1) * 161) + (1.75 * 161) = 603.75 gates. Unfortunately, the DLog PoK gadget cannot be laid
  out as compatible with set membership (TODO: Further work on this?).

  The DLog PoK works by creating a divisor which interpolates a series of points which sum to 0.
  Notably, we only check their x coordinates interpolate to 0. This allows malleability.

  Instead of proving A + B + C = 0, a 'malicious' prover can prove A - B + C sums to 0.
  This isn't an issue as anyone who knows the DLog with negatives can calculate the DLog without
  negatives. Therefore, knowledge of the DLog with negatives implies knowledge of the DLog without
  them.

  We take advantage of this by proving knowledge of some sum of G*3**i. Using a trinary system of
  [-1, 0, 1], we can prove a 2**256 DLog in just 161 points with just 161 bits for selections.

  3 ** 161 ~= 2 ** 256
  161 + (1.75 * 161) = 442.75

  TODO: The curve trees paper describes a 3-bit lookup with just 5 gates, beating the above
  commentary which was n - 1.

  2 ** 3 = 8
  The set of 0G ..= 7G + -(0G ..= 7G) has 15 elements.
  15 ** 65 ~= 2 ** 256
  (5 * 65) + (1.75 * 65) = 438.75

  We'd save 4 gates by implementing it.

  If a 2-bit lookup can be done with three gates, it'd save 10 gates. It'd save 101 if it can be
  done with just two gates. Arkwork's implementativon uses three gates.
*/
// TODO: Transcript this
#[derive(Debug)]
pub struct DLogTable<C: Ecip>(Vec<C::G>, Vec<C::FieldElement>, usize);
impl<C: Ecip> DLogTable<C> {
  pub fn new(point: C::G) -> DLogTable<C> {
    assert!(point != C::G::identity(), "creating a DLogTable for identity");

    // Mutual amount of bits
    // TODO: This assumes this is being used in a cycle, not a tower
    let CAPACITY = C::F::CAPACITY.min(C::FieldElement::CAPACITY);
    // Maximum value representable in this mutual amount of bits
    let max = C::F::from(2).pow([u64::from(CAPACITY)]) - C::F::ONE;
    // Trits needed for this maximum value
    // TODO: Technically, this is a bit indirect
    // It should be the amount of trits which will fit into both fields, not the amount of trits
    // which will fit into the mutual capacity of both fields
    let mut trits = scalar_to_trits::<C>(max);
    while trits.last().expect("maximum scalar was 0") == &Trit::Zero {
      trits.pop();
    }
    let trits = trits.len();

    let mut G_pow_3 = vec![point; trits];
    for i in 1 .. trits {
      G_pow_3[i] = G_pow_3[i - 1].double() + G_pow_3[i - 1];
    }
    let mut xs = vec![];
    for G in &G_pow_3 {
      xs.push(C::to_xy(*G).0);
    }
    DLogTable(G_pow_3, xs, trits)
  }

  pub fn trits(&self) -> usize {
    self.0.len()
  }

  pub fn generator(&self) -> C::G {
    self.0[0]
  }
}

// y, yx, x, zero coeffs
type DivisorCoeffs = (usize, usize, usize, usize);
fn divisor_coeffs(points: usize) -> DivisorCoeffs {
  let y_coeffs = if points > 2 { 1 } else { 0 }; // TODO: Is this line correct?
  let yx_coeffs = (points / 2).saturating_sub(2);
  let x_coeffs = points / 2;
  let zero_coeffs = 1;
  (y_coeffs, yx_coeffs, x_coeffs, zero_coeffs)
}

#[derive(Clone, Debug)]
struct EmbeddedDivisor {
  y_coeff: Option<ProductReference>,
  yx_coeffs: Vec<ProductReference>,
  x_coeffs: Vec<ProductReference>,
  zero_coeff: ProductReference,
  differentiated: bool,
}

impl EmbeddedDivisor {
  #[allow(clippy::new_ret_no_self)]
  fn new<T: 'static + Transcript, C: EmbeddedCurveOperations>(
    circuit: &mut Circuit<T, C>,
    points: usize,
    divisor: &Option<Poly<<C::Embedded as Ecip>::FieldElement>>,
  ) -> EmbeddedDivisor {
    assert_eq!(circuit.prover(), divisor.is_some());
    assert_eq!(points % 2, 0, "odd amounts of points aren't currently supported"); // TODO

    let coeffs = divisor_coeffs(points);
    if let Some(divisor) = divisor.as_ref() {
      assert!(coeffs.0 <= 1);
      assert!(coeffs.0 >= divisor.y_coefficients.len());
      assert!(coeffs.1 >= divisor.yx_coefficients.get(0).unwrap_or(&vec![]).len());
      assert!(coeffs.2 >= divisor.x_coefficients.len());
      assert_eq!(coeffs.3, 1);
    }

    // Create a serial representation
    let serial = if let Some(divisor) = divisor.as_ref() {
      let mut serial = vec![];
      for y_coeff in &divisor.y_coefficients {
        serial.push(Some(*y_coeff));
      }
      for _ in divisor.y_coefficients.len() .. coeffs.0 {
        serial.push(Some(<C::Embedded as Ecip>::FieldElement::ZERO));
      }

      for yx_coeff in divisor.yx_coefficients.get(0).unwrap_or(&vec![]) {
        serial.push(Some(*yx_coeff));
      }
      for _ in divisor.yx_coefficients.get(0).unwrap_or(&vec![]).len() .. coeffs.1 {
        serial.push(Some(<C::Embedded as Ecip>::FieldElement::ZERO));
      }

      // TODO: Don't transcript the first x coeff, use 1 directly
      for x_coeff in &divisor.x_coefficients {
        serial.push(Some(*x_coeff));
      }
      for _ in divisor.x_coefficients.len() .. coeffs.2 {
        serial.push(Some(<C::Embedded as Ecip>::FieldElement::ZERO));
      }

      serial.push(Some(divisor.zero_coefficient));
      serial
    } else {
      vec![None; coeffs.0 + coeffs.1 + coeffs.2 + coeffs.3]
    };

    // Commit in pairs
    let mut iter = serial.into_iter();
    let mut serial = VecDeque::new();
    while let Some(a) = iter.next() {
      let b = iter.next().unwrap_or(a);
      let a = circuit.add_secret_input(a);
      let b = circuit.add_secret_input(b);
      // GC: 0.5 per point
      let ((l, r, _), _) = circuit.product(a, b);
      serial.push_back(l);
      serial.push_back(r);
    }

    // Decompose back
    let y_coeff = if coeffs.0 == 1 { Some(serial.pop_front().unwrap()) } else { None };
    let mut yx_coeffs = vec![];
    for _ in 0 .. coeffs.1 {
      yx_coeffs.push(serial.pop_front().unwrap());
    }
    let mut x_coeffs = vec![];
    for _ in 0 .. coeffs.2 {
      x_coeffs.push(serial.pop_front().unwrap());
    }
    let zero_coeff = serial.pop_front().unwrap();
    assert_eq!(serial.len(), (coeffs.0 + coeffs.1 + coeffs.2 + coeffs.3) % 2);

    debug_assert_eq!(
      coeffs,
      (usize::from(u8::from(y_coeff.is_some())), yx_coeffs.len(), x_coeffs.len(), 1)
    );

    EmbeddedDivisor { y_coeff, yx_coeffs, x_coeffs, zero_coeff, differentiated: false }
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DivisorChallenge<'a, C: Ecip>(&'a [C::FieldElement]);
impl<C: Ecip> DivisorChallenge<'_, C> {
  fn new<T: Transcript>(points: usize, challenge: T::Challenge) -> Vec<C::FieldElement> {
    let point = C::to_xy(C::hash_to_G("bp+_ecip", challenge.as_ref()));
    let (_y_coeff, yx_coeffs, x_coeffs, _zero_coeff) = divisor_coeffs(points);

    // This debug assert makes sure we don't need to use a max statement
    // While we could remove it for a max statement, this not holding means some significant
    // structural changes to the polynomial occured, which are assumed abnormal
    debug_assert!(x_coeffs > yx_coeffs, "yx_coeffs had more terms than x_coeffs");

    let mut res = Vec::with_capacity(x_coeffs + 1);
    res.push(point.1);

    // Create the powers of x
    res.push(point.0);
    while res.len() < (1 + x_coeffs) {
      res.push(*res.last().unwrap() * point.0);
    }

    res
  }

  fn y_coeff(&self, negative: bool) -> C::FieldElement {
    if negative {
      -self.0[0]
    } else {
      self.0[0]
    }
  }

  fn x_coeffs(&self) -> &[C::FieldElement] {
    &self.0[1 ..]
  }
}

impl EmbeddedDivisor {
  fn eval<C: EmbeddedCurveOperations>(
    &self,
    challenge: ChallengeReference,
    neg_y: bool,
  ) -> Constraint<C> {
    let mut constraint = Constraint::new("divisor_eval");

    if let Some(y_coeff) = self.y_coeff {
      constraint.weight_with_challenge(
        y_coeff,
        challenge,
        Box::new(move |challenge| DivisorChallenge::<C::Embedded>(challenge).y_coeff(neg_y)),
      );
    }

    let differentiated = self.differentiated;
    for (i, yx_coeff) in self.yx_coeffs.iter().enumerate() {
      constraint.weight_with_challenge(
        *yx_coeff,
        challenge,
        Box::new(move |challenge| {
          let challenge = DivisorChallenge::<C::Embedded>(challenge);
          (if differentiated {
            challenge.x_coeffs()[i] *
              <C::Embedded as Ecip>::FieldElement::from(u64::try_from(i + 2).unwrap())
          } else {
            challenge.x_coeffs()[i]
          }) * challenge.y_coeff(neg_y)
        }),
      );
    }

    for (i, x_coeff) in self.x_coeffs.iter().enumerate() {
      constraint.weight_with_challenge(
        *x_coeff,
        challenge,
        Box::new(move |challenge| {
          let challenge = DivisorChallenge::<C::Embedded>(challenge);
          if differentiated {
            challenge.x_coeffs()[i] *
              <C::Embedded as Ecip>::FieldElement::from(u64::try_from(i + 2).unwrap())
          } else {
            challenge.x_coeffs()[i]
          }
        }),
      );
    }

    constraint.weight(self.zero_coeff, <C::Embedded as Ecip>::FieldElement::ONE);

    constraint
  }
}

// This uses a divisor to prove knowledge of a DLog with just 1.5 gates per point, plus a
// constant 8 gates
// This is more than twice as performant as incomplete addition and is closer to being complete
// (only identity is unsupported)
//
// Gate count is notated GC

// TODO: Each arithmetic circuit gate is two IP rows. The currently implemented vector commitment
// scheme adds 2 rows per item, with 3 items in each gate (left, right, output)
// This means the cost goes from 1.5 gates per point to 6, making it less efficient than incomplete
// addition for proofs not already incurring the vector commitment scheme's overhead
// We *need* a zero-overhead vector commitment scheme

// TODO: Can we impl a batch DLog PoK?
pub(crate) fn divisor_dlog_pok<
  R: RngCore + CryptoRng,
  T: 'static + Transcript,
  C: EmbeddedCurveOperations,
>(
  rng: &mut R,
  circuit: &mut Circuit<T, C>,
  G: &'static DLogTable<C::Embedded>,
  p: OnCurvePoint,
  dlog: Option<<C::Embedded as Ciphersuite>::F>,
) {
  let (bits, Gs) = if circuit.prover() {
    let dlog = dlog.expect("DLog wasn't available to the prover");
    {
      let (x, y) = C::Embedded::to_xy(G.0[0] * dlog);
      debug_assert_eq!(
        circuit.unchecked_value(p.x),
        x,
        "proving DLog PoK for a point with a distinct DLog"
      );
      debug_assert_eq!(circuit.unchecked_value(p.y), y, "proving DLog PoK for -point");
    }

    let mut trits = scalar_to_trits::<C::Embedded>(dlog);

    // TODO: This block is not const time
    {
      trits.truncate(G.2);
      while trits.len() < G.2 {
        trits.push(Trit::Zero);
      }
      debug_assert_eq!(trits.len(), G.2);
    }

    let mut bits = vec![];
    let mut Gs = vec![];
    for (i, trit) in trits.iter().enumerate() {
      bits.push(Some(Choice::from(u8::conditional_select(&1, &0, trit.ct_eq(&Trit::Zero)))));
      let G = <C::Embedded as Ciphersuite>::G::conditional_select(
        &G.0[i],
        &<C::Embedded as Ciphersuite>::G::identity(),
        trit.ct_eq(&Trit::Zero),
      );
      Gs.push(<C::Embedded as Ciphersuite>::G::conditional_select(
        &G,
        &-G,
        trit.ct_eq(&Trit::NegOne),
      ));
    }
    (bits, Some(Gs))
  } else {
    (vec![None; G.2], None)
  };

  // GC: 1 per point
  let mut dlog = Vec::with_capacity(bits.len());
  for bit in bits {
    dlog.push(Bit::new_from_choice(circuit, bit));
  }

  let points = G.2 + 1;

  // Create the divisor
  let divisor = if circuit.prover() {
    let mut Gs = Gs.expect("prover didn't populate Gs");
    Gs.push(-C::Embedded::from_xy(circuit.unchecked_value(p.x), circuit.unchecked_value(p.y)));
    debug_assert_eq!(Gs.len(), points);

    // Drop all Gs which are identity
    let without_identity =
      Gs.drain(..).filter(|G| !bool::from(G.is_identity())).collect::<Vec<_>>();
    drop(Gs);
    assert!(
      without_identity.len() >= 2,
      "invalid amount of points. either {} or {}",
      "0 (proving [] == identity, when we need a non-zero divisor)",
      "1 (a non-identity x == identity, which is false)",
    );

    Some(Divisor::<C::Embedded>::new(&without_identity).normalize_x_coefficient())
  } else {
    None
  };
  let embedded = EmbeddedDivisor::new(circuit, points, &divisor);

  // Make sure the divisor isn't zero
  // TODO: Don't add it in-circuit in the first place
  circuit.equals_constant(embedded.x_coeffs[0], C::F::ONE);

  // We need to select a challenge point for the divisor
  // This requires committing to the divisor, a ZK variable
  // We do this by creating a vector commitment for the divisor's variables
  // This commitment is then what's hashed for challenges
  let commitment = {
    let mut transcript = embedded.x_coeffs.clone();
    transcript.extend(&embedded.yx_coeffs);
    transcript.push(embedded.zero_coeff);
    if let Some(y_coeff) = embedded.y_coeff {
      transcript.push(y_coeff);
    }

    // Also transcript the DLog
    for bit in &dlog {
      // Note: We can only bind a single element, the re-composition of the DLog, if desirable
      // It'd be a single sharable gate and one constraint
      transcript
        .push(circuit.variable_to_product(bit.variable).expect("bit was created without a gate"));
    }

    // And finally the point itself
    transcript
      .push(circuit.variable_to_product(p.x).expect("on-curve check didn't use x in a gate"));
    transcript
      .push(circuit.variable_to_product(p.y).expect("on-curve check didn't use y in a gate"));

    // Create the commitment
    let commitment = circuit.allocate_vector_commitment();
    circuit.bind(commitment, transcript, None);
    circuit.finalize_commitment(commitment, Some(C::F::random(rng)).filter(|_| circuit.prover()));
    commitment
  };

  let (challenge, challenge_actual) = circuit.in_circuit_challenge(
    commitment,
    Box::new(move |challenge| DivisorChallenge::<C::Embedded>::new::<T>(points, challenge)),
  );

  // Differentiate the divisor
  let differentiated = divisor.as_ref().map(Poly::differentiate);

  // The following comments are taken from the EC IP library
  /*
    Differentation by x practically involves:
    - Dropping everything without an x component
    - Shifting everything down a power of x
    - If the x power is greater than 2, multiplying the new term's coefficient by the x power in
      question
  */
  let dx = {
    // The following can panic for elliptic curves with a capacity in trits < 4
    // These are considered too trivial to be worth writing code for
    let mut yx_coeffs = embedded.yx_coeffs.clone();
    let y_coeff = yx_coeffs.remove(0);
    let mut x_coeffs = embedded.x_coeffs.clone();
    let zero_coeff = x_coeffs.remove(0);
    // Each yx/x coefficient needs weighting by `i + 2`, where i is its zero-indexed position
    EmbeddedDivisor {
      y_coeff: Some(y_coeff),
      yx_coeffs,
      x_coeffs,
      zero_coeff,
      differentiated: true,
    }
  };

  /*
    Differentation by y is trivial
    It's the y coefficient as the zero coefficient, and the yx coefficients as the x
    coefficients
    This is thanks to any y term over y^2 being reduced out
  */
  let dy = EmbeddedDivisor {
    y_coeff: None,
    yx_coeffs: vec![],
    x_coeffs: embedded.yx_coeffs.clone(),
    zero_coeff: embedded.y_coeff.expect("divisor didn't have a y coefficient?"),
    // Sets differentiated = false since despite being differentiated, it doesn't require weighting
    // This is because all of the powers differentiated were 1, so the only weight needed is 1
    differentiated: false,
  };

  // Evaluate the logarithmic derivative for challenge, -challenge

  // The logarithmic derivative is (dx(x, y) + (dy(x, y) * div_formula)) / D, whre div_formula is:
  //   (3*x^2 + A) / (2*y)

  let div_formula = |x: <C::Embedded as Ecip>::FieldElement,
                     y: <C::Embedded as Ecip>::FieldElement| {
    let xsq = x.square();
    ((xsq.double() + xsq) + <C::Embedded as Ecip>::FieldElement::from(<C::Embedded as Ecip>::A)) *
      Option::<<C::Embedded as Ecip>::FieldElement>::from(y.double().invert())
        .expect("challenge y was zero")
  };

  // Eval dx(x, y)
  let dx_eval_constraint = dx.eval(challenge, false);
  let dx_eval = circuit.add_secret_input(
    challenge_actual
      .as_ref()
      .map(|challenge| differentiated.as_ref().unwrap().0.eval(challenge[1], challenge[0])),
  );
  circuit.set_variable_constraint(dx_eval, dx_eval_constraint);

  // Eval dx(x, -y)
  let neg_dx_eval_constraint: Constraint<C> = dx.eval(challenge, true);
  let neg_dx_eval = circuit.add_secret_input(
    challenge_actual
      .as_ref()
      .map(|challenge| differentiated.as_ref().unwrap().0.eval(challenge[1], -challenge[0])),
  );
  circuit.set_variable_constraint(neg_dx_eval, neg_dx_eval_constraint);

  // dy(y) * div_formula
  let dy_div_formula = {
    let dy_eval_constraint: Constraint<C> = dy.eval(challenge, false);
    let dy_eval = circuit.add_secret_input(
      challenge_actual
        .as_ref()
        .map(|challenge| differentiated.as_ref().unwrap().1.eval(challenge[1], challenge[0])),
    );
    circuit.set_variable_constraint(dy_eval, dy_eval_constraint);

    let div_formula_eval = circuit.add_secret_input(
      challenge_actual.as_ref().map(|challenge| div_formula(challenge[1], challenge[0])),
    );
    {
      let mut constraint: Constraint<C> = Constraint::new("div_formula");
      constraint.rhs_offset_with_challenge(
        challenge,
        Box::new(move |challenge| {
          // - since the variable is subtracted from the lhs
          -div_formula(challenge[1], challenge[0])
        }),
      );
      circuit.set_variable_constraint(div_formula_eval, constraint);
    }

    // GC: 1
    circuit.product(dy_eval, div_formula_eval).0 .2
  };

  // Eval dy(-y) * div_formula
  let neg_dy_div_formula = {
    let neg_dy_eval_constraint: Constraint<C> = dy.eval(challenge, true);
    let neg_dy_eval = circuit.add_secret_input(
      challenge_actual
        .as_ref()
        .map(|challenge| differentiated.as_ref().unwrap().1.eval(challenge[1], -challenge[0])),
    );
    circuit.set_variable_constraint(neg_dy_eval, neg_dy_eval_constraint);

    // TODO: We should be able to cache and negate the first div_formula call
    let neg_div_formula = circuit.add_secret_input(
      challenge_actual.as_ref().map(|challenge| div_formula(challenge[1], -challenge[0])),
    );
    {
      let mut constraint: Constraint<C> = Constraint::new("neg_div_formula");
      constraint.rhs_offset_with_challenge(
        challenge,
        Box::new(move |challenge| {
          // - since the variable is subtracted from the lhs
          -div_formula(challenge[1], -challenge[0])
        }),
      );
      circuit.set_variable_constraint(neg_div_formula, constraint);
    }

    // GC: 1
    circuit.product(neg_dy_eval, neg_div_formula).0 .2
  };

  // We still have to do (dx + dy_div_formula) / D
  // That requires the dx evaluations being committed to
  // GC: 1
  let ((dx_eval, neg_dx_eval, _), _) = circuit.product(dx_eval, neg_dx_eval);

  // TODO: Write a single function to eval dx, dy, then delete the duplicated -y code

  // Eval D
  let d_eval_constraint: Constraint<C> = embedded.eval(challenge, false);
  let d_eval_raw = challenge_actual
    .as_ref()
    .map(|challenge| divisor.as_ref().unwrap().eval(challenge[1], challenge[0]));
  let d_eval = circuit.add_secret_input(d_eval_raw);
  circuit.set_variable_constraint(d_eval, d_eval_constraint);

  // Eval D for -y
  let neg_d_eval_constraint: Constraint<C> = embedded.eval(challenge, true);
  let neg_d_eval_raw = challenge_actual
    .as_ref()
    .map(|challenge| divisor.as_ref().unwrap().eval(challenge[1], -challenge[0]));
  let neg_d_eval = circuit.add_secret_input(neg_d_eval_raw);
  circuit.set_variable_constraint(neg_d_eval, neg_d_eval_constraint);

  // We now need the inverse of d_eval and neg_d_eval
  let d_inv = circuit.add_secret_input(d_eval_raw.map(|d| {
    Option::<<C::Embedded as Ecip>::FieldElement>::from(d.invert())
      .expect("divisor evaluated to zero")
  }));
  // GC: 1
  // TODO: Gadget out inversions
  let ((_, d_inv, one), _) = circuit.product(d_eval, d_inv);
  circuit.equals_constant(one, C::F::ONE);

  let neg_d_inv = circuit.add_secret_input(neg_d_eval_raw.map(|d| {
    Option::<<C::Embedded as Ecip>::FieldElement>::from(d.invert())
      .expect("divisor evaluated to zero")
  }));
  // GC: 1
  let ((_, neg_d_inv, one), _) = circuit.product(neg_d_eval, neg_d_inv);
  circuit.equals_constant(one, C::F::ONE);

  // Eval (dx + dy_div_formula) / D
  let dx_dy_div_formula = circuit.add_secret_input(if circuit.prover() {
    Some(
      circuit.unchecked_value(dx_eval.variable()) +
        circuit.unchecked_value(dy_div_formula.variable()),
    )
  } else {
    None
  });
  {
    let mut constraint: Constraint<C> = Constraint::new("dx_dy_div_formula");
    constraint.weight(dx_eval, C::F::ONE);
    constraint.weight(dy_div_formula, C::F::ONE);
    circuit.set_variable_constraint(dx_dy_div_formula, constraint);
  }
  // GC: 1
  let y_res = circuit.product(dx_dy_div_formula, d_inv.variable()).0 .2;

  // Eval (neg_dx + neg_dy_div_formula) / D
  let neg_dx_dy_div_formula = circuit.add_secret_input(if circuit.prover() {
    Some(
      circuit.unchecked_value(neg_dx_eval.variable()) +
        circuit.unchecked_value(neg_dy_div_formula.variable()),
    )
  } else {
    None
  });
  {
    let mut constraint: Constraint<C> = Constraint::new("neg_dx_dy_div_formula");
    constraint.weight(neg_dx_eval, C::F::ONE);
    constraint.weight(neg_dy_div_formula, C::F::ONE);
    circuit.set_variable_constraint(neg_dx_dy_div_formula, constraint);
  }
  // GC: 1
  let neg_y_res = circuit.product(neg_dx_dy_div_formula, neg_d_inv.variable()).0 .2;

  if circuit.prover() {
    let log_deriv = divisor.as_ref().unwrap().logarithmic_derivative::<C::Embedded>();
    let y = challenge_actual.as_ref().unwrap()[0];
    let x = challenge_actual.as_ref().unwrap()[1];

    assert_eq!(
      circuit.unchecked_value(y_res.variable()),
      (log_deriv.numerator.eval(x, y) *
        Option::<<C::Embedded as Ecip>::FieldElement>::from(
          log_deriv.denominator.eval(x, y).invert(),
        )
        .expect("denominator eval'd to 0"))
    );
    assert_eq!(
      circuit.unchecked_value(neg_y_res.variable()),
      (log_deriv.numerator.eval(x, -y) *
        Option::<<C::Embedded as Ecip>::FieldElement>::from(
          log_deriv.denominator.eval(x, -y).invert()
        )
        .expect("denominator eval'd to 0"))
    );
  }

  // y_res + neg_y_res should equal Sum(bit * (1 / (c.x - Gi.x))) + (1 / (c.x - P.x))
  let mut interpolates: Constraint<C> = Constraint::new("dlog_pok_final");
  // Add the rhs to the constraint's lhs
  for (x, bit) in G.1.iter().zip(dlog.iter()) {
    interpolates.weight_with_challenge(
      circuit.variable_to_product(bit.variable).unwrap(),
      challenge,
      Box::new(move |challenge: &[<C::Embedded as Ecip>::FieldElement]| {
        Option::<<C::Embedded as Ecip>::FieldElement>::from((challenge[1] - x).invert())
          .expect("challenge point was one of the tabled points")
      }),
    );
  }

  // Invert c.x - P.x
  let c_x_minus_point_x = circuit.add_secret_input(if circuit.prover() {
    Some(challenge_actual.as_ref().unwrap()[1] - circuit.unchecked_value(p.x))
  } else {
    None
  });

  let c_x_minus_point_x_inv = circuit.add_secret_input(if circuit.prover() {
    Some(
      Option::<<C::Embedded as Ecip>::FieldElement>::from(
        circuit.unchecked_value(c_x_minus_point_x).invert(),
      )
      .expect("challenge x was equivalent to point's"),
    )
  } else {
    None
  });

  // GC: 1
  let ((c_x_minus_point_x, c_x_minus_point_x_inv, one), _) =
    circuit.product(c_x_minus_point_x, c_x_minus_point_x_inv);
  {
    let mut c_x_minus_point_x_constraint: Constraint<C> = Constraint::new("c_x_minus_point_x");
    // 0 = -c.x
    c_x_minus_point_x_constraint.rhs_offset_with_challenge(
      challenge,
      Box::new(|challenge: &[<C::Embedded as Ecip>::FieldElement]| -challenge[1]),
    );
    // -P.x = -c.x
    c_x_minus_point_x_constraint.weight(
      circuit
        .variable_to_product(p.x)
        .expect("p.x didn't have a ProductReference, which it would if on-curve checked"),
      -C::F::ONE,
    );
    // -P.x - (c.x - P.x) = -c.x
    // -P.x - c.x + P.x = -c.x
    // -c.x = -c.x
    c_x_minus_point_x_constraint.weight(c_x_minus_point_x, -C::F::ONE);
    circuit.constrain(c_x_minus_point_x_constraint);
    circuit.equals_constant(one, C::F::ONE);
  }
  interpolates.weight(c_x_minus_point_x_inv, C::F::ONE);

  interpolates.weight(y_res, -C::F::ONE);
  interpolates.weight(neg_y_res, -C::F::ONE);
  circuit.constrain(interpolates);
}
