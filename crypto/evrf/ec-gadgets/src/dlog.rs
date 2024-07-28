use core::fmt;

use ciphersuite::{
  group::ff::{Field, PrimeField, BatchInverter},
  Ciphersuite,
};

use generalized_bulletproofs_circuit_abstraction::*;

use crate::*;

/// Parameters for a discrete logarithm proof.
///
/// This isn't required to be implemented by the Field/Group/Ciphersuite, solely a struct, to
/// enable parameterization of discrete log proofs to the bitlength of the discrete logarithm.
/// While that may be F::NUM_BITS, a discrete log proof a for a full scalar, it could also be 64,
/// a discrete log proof for a u64 (such as if opening a Pedersen commitment in-circuit).
pub trait DiscreteLogParameters {
  /// The amount of bits used to represent a scalar.
  type ScalarBits: ArrayLength;

  /// The amount of x**i coefficients in a divisor.
  ///
  /// This is the amount of points in a divisor (the amount of bits in a scalar, plus one) divided
  /// by two.
  type XCoefficients: ArrayLength;

  /// The amount of x**i coefficients in a divisor, minus one.
  type XCoefficientsMinusOne: ArrayLength;

  /// The amount of y x**i coefficients in a divisor.
  ///
  /// This is the amount of points in a divisor (the amount of bits in a scalar, plus one) divided
  /// by two, minus two.
  type YxCoefficients: ArrayLength;
}

/// A tabled generator for proving/verifying discrete logarithm claims.
#[derive(Clone)]
pub struct GeneratorTable<F: PrimeField, Parameters: DiscreteLogParameters>(
  GenericArray<(F, F), Parameters::ScalarBits>,
);

impl<F: PrimeField, Parameters: DiscreteLogParameters> fmt::Debug
  for GeneratorTable<F, Parameters>
{
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("GeneratorTable")
      .field("x", &self.0[0].0)
      .field("y", &self.0[0].1)
      .finish_non_exhaustive()
  }
}

impl<F: PrimeField, Parameters: DiscreteLogParameters> GeneratorTable<F, Parameters> {
  /// Create a new table for this generator.
  ///
  /// The generator is assumed to be well-formed and on-curve. This function may panic if it's not.
  pub fn new(curve: &CurveSpec<F>, generator_x: F, generator_y: F) -> Self {
    // mdbl-2007-bl
    fn dbl<F: PrimeField>(a: F, x1: F, y1: F) -> (F, F) {
      let xx = x1 * x1;
      let w = a + (xx + xx.double());
      let y1y1 = y1 * y1;
      let r = y1y1 + y1y1;
      let sss = (y1 * r).double().double();
      let rr = r * r;

      let b = x1 + r;
      let b = (b * b) - xx - rr;

      let h = (w * w) - b.double();
      let x3 = h.double() * y1;
      let y3 = (w * (b - h)) - rr.double();
      let z3 = sss;

      // Normalize from XYZ to XY
      let z3_inv = z3.invert().unwrap();
      let x3 = x3 * z3_inv;
      let y3 = y3 * z3_inv;

      (x3, y3)
    }

    let mut res = Self(GenericArray::default());
    res.0[0] = (generator_x, generator_y);
    for i in 1 .. Parameters::ScalarBits::USIZE {
      let last = res.0[i - 1];
      res.0[i] = dbl(curve.a, last.0, last.1);
    }

    res
  }
}

/// A representation of the divisor.
///
/// The coefficient for x**1 is explicitly excluded as it's expected to be normalized to 1.
#[derive(Clone)]
pub struct Divisor<Parameters: DiscreteLogParameters> {
  /// The coefficient for the `y` term of the divisor.
  ///
  /// There is never more than one `y**i x**0` coefficient as the leading term of the modulus is
  /// `y**2`. It's assumed the coefficient is non-zero (and present) as it will be for any divisor
  /// exceeding trivial complexity.
  pub y: Variable,
  /// The coefficients for the `y**1 x**i` terms of the polynomial.
  // This subtraction enforces the divisor to have at least 4 points which is acceptable.
  // TODO: Double check these constants
  pub yx: GenericArray<Variable, Parameters::YxCoefficients>,
  /// The coefficients for the `x**i` terms of the polynomial, skipping x**1.
  ///
  /// x**1 is skipped as it's expected to be normalized to 1, and therefore constant, in order to
  /// ensure the divisor is non-zero (as necessary for the proof to be complete).
  // Subtract 1 from the length due to skipping the coefficient for x**1
  pub x_from_power_of_2: GenericArray<Variable, Parameters::XCoefficientsMinusOne>,
  /// The constant term in the polynomial (alternatively, the coefficient for y**0 x**0).
  pub zero: Variable,
}

/// A point, its discrete logarithm, and the divisor to prove it.
#[derive(Clone)]
pub struct PointWithDlog<Parameters: DiscreteLogParameters> {
  /// The point which is supposedly the result of scaling the generator by the discrete logarithm.
  pub point: (Variable, Variable),
  /// The discrete logarithm, represented as coefficients of a polynomial of 2**i.
  pub dlog: GenericArray<Variable, Parameters::ScalarBits>,
  /// The divisor interpolating the relevant doublings of generator with the inverse of the point.
  pub divisor: Divisor<Parameters>,
}

/// A struct containing a point used for the evaluation of a divisor.
///
/// Preprocesses and caches as much of the calculation as possible to minimize work upon reuse of
/// challenge points.
struct ChallengePoint<F: PrimeField, Parameters: DiscreteLogParameters> {
  y: F,
  yx: GenericArray<F, Parameters::YxCoefficients>,
  x: GenericArray<F, Parameters::XCoefficients>,
  p_0_n_0: F,
  x_p_0_n_0: GenericArray<F, Parameters::YxCoefficients>,
  p_1_n: F,
  p_1_d: F,
}

impl<F: PrimeField, Parameters: DiscreteLogParameters> ChallengePoint<F, Parameters> {
  fn new(
    curve: &CurveSpec<F>,
    // The slope between all of the challenge points
    slope: F,
    // The x and y coordinates
    x: F,
    y: F,
    // The inversion of twice the y coordinate
    // We accept this as an argument so that the caller can calculcate these with a batch inversion
    inv_two_y: F,
  ) -> Self {
    // Powers of x, skipping x**0
    let divisor_x_len = Parameters::XCoefficients::USIZE;
    let mut x_pows = GenericArray::default();
    x_pows[0] = x;
    for i in 1 .. divisor_x_len {
      let last = x_pows[i - 1];
      x_pows[i] = last * x;
    }

    // Powers of x multiplied by y
    let divisor_yx_len = Parameters::YxCoefficients::USIZE;
    let mut yx = GenericArray::default();
    // Skips x**0
    yx[0] = y * x;
    for i in 1 .. divisor_yx_len {
      let last = yx[i - 1];
      yx[i] = last * x;
    }

    let x_sq = x.square();
    let three_x_sq = x_sq.double() + x_sq;
    let three_x_sq_plus_a = three_x_sq + curve.a;
    let two_y = y.double();

    // p_0_n_0 from `DivisorChallenge`
    let p_0_n_0 = three_x_sq_plus_a * inv_two_y;
    let mut x_p_0_n_0 = GenericArray::default();
    // Since this iterates over x, which skips x**0, this also skips p_0_n_0 x**0
    for (i, x) in x_pows.iter().take(divisor_yx_len).enumerate() {
      x_p_0_n_0[i] = p_0_n_0 * x;
    }

    // p_1_n from `DivisorChallenge`
    let p_1_n = two_y;
    // p_1_d from `DivisorChallenge`
    let p_1_d = (-slope * p_1_n) + three_x_sq_plus_a;

    ChallengePoint { x: x_pows, y, yx, p_0_n_0, x_p_0_n_0, p_1_n, p_1_d }
  }
}

// `DivisorChallenge` from the section `Discrete Log Proof`
fn divisor_challenge_eval<C: Ciphersuite, Parameters: DiscreteLogParameters>(
  circuit: &mut Circuit<C>,
  divisor: &Divisor<Parameters>,
  challenge: &ChallengePoint<C::F, Parameters>,
) -> Variable {
  // The evaluation of the divisor differentiated by y, further multiplied by p_0_n_0
  // Differentation drops everything without a y coefficient, and drops what remains by a power
  // of y
  // (y**1 -> y**0, yx**i -> x**i)
  // This aligns with p_0_n_1  from `DivisorChallenge`
  let p_0_n_1 = {
    let mut p_0_n_1 = LinComb::empty().term(challenge.p_0_n_0, divisor.y);
    for (j, var) in divisor.yx.iter().enumerate() {
      // This does not raise by `j + 1` as x_p_0_n_0 omits x**0
      p_0_n_1 = p_0_n_1.term(challenge.x_p_0_n_0[j], *var);
    }
    p_0_n_1
  };

  // The evaluation of the divisor differentiated by x
  // This aligns with p_0_n_2  from `DivisorChallenge`
  let p_0_n_2 = {
    // The coefficient for x**1 is 1, so 1 becomes the new zero coefficient
    let mut p_0_n_2 = LinComb::empty().constant(C::F::ONE);

    // Handle the new y coefficient
    p_0_n_2 = p_0_n_2.term(challenge.y, divisor.yx[0]);

    // Handle the new yx coefficients
    for (j, yx) in divisor.yx.iter().enumerate().skip(1) {
      // For the power which was shifted down, we multiply this coefficient
      // 3 x**2 -> 2 * 3 x**1
      let original_power_of_x = C::F::from(u64::try_from(j + 1).unwrap());
      // `j - 1` so `j = 1` indexes yx[0] as yx[0] is the y x**1
      // (yx omits y x**0)
      let this_weight = original_power_of_x * challenge.yx[j - 1];
      p_0_n_2 = p_0_n_2.term(this_weight, *yx);
    }

    // Handle the x coefficients
    // We don't skip the first one as `x_from_power_of_2` already omits x**1
    for (i, x) in divisor.x_from_power_of_2.iter().enumerate() {
      // i + 2 as the paper expects i to start from 1 and be + 1, yet we start from 0
      let original_power_of_x = C::F::from(u64::try_from(i + 2).unwrap());
      // Still x[i] as x[0] is x**1
      let this_weight = original_power_of_x * challenge.x[i];

      p_0_n_2 = p_0_n_2.term(this_weight, *x);
    }

    p_0_n_2
  };

  // p_0_n from `DivisorChallenge`
  let p_0_n = p_0_n_1 + &p_0_n_2;

  // Evaluation of the divisor
  // p_0_d from `DivisorChallenge`
  let p_0_d = {
    let mut p_0_d = LinComb::empty().term(challenge.y, divisor.y);

    for (var, c_yx) in divisor.yx.iter().zip(&challenge.yx) {
      p_0_d = p_0_d.term(*c_yx, *var);
    }

    for (i, var) in divisor.x_from_power_of_2.iter().enumerate() {
      // This `i+1` is preserved, despite most not being as x omits x**0, as this assumes we
      // start with `i=1`
      p_0_d = p_0_d.term(challenge.x[i + 1], *var);
    }

    // Adding x effectively adds a `1 x` term, ensuring the divisor isn't 0
    p_0_d.term(C::F::ONE, divisor.zero).constant(challenge.x[0])
  };

  // Calculate the joint numerator
  // p_n from `DivisorChallenge`
  let p_n = p_0_n * challenge.p_1_n;
  // Calculate the joint denominator
  // p_d from `DivisorChallenge`
  let p_d = p_0_d * challenge.p_1_d;

  // We want `n / d = o`
  // `n / d = o` == `n = d * o`
  // These are safe unwraps as they're solely done by the prover and should always be non-zero
  let witness =
    circuit.eval(&p_d).map(|p_d| (p_d, circuit.eval(&p_n).unwrap() * p_d.invert().unwrap()));
  let (_l, o, n_claim) = circuit.mul(Some(p_d), None, witness);
  circuit.equality(p_n, &n_claim.into());
  o
}

/// A challenge to evaluate divisors with.
///
/// This challenge must be sampled after writing the commitments to the transcript. This challenge
/// is reusable across various divisors.
pub struct DiscreteLogChallenge<F: PrimeField, Parameters: DiscreteLogParameters> {
  c0: ChallengePoint<F, Parameters>,
  c1: ChallengePoint<F, Parameters>,
  c2: ChallengePoint<F, Parameters>,
  slope: F,
  intercept: F,
}

/// A generator which has been challenged and is ready for use in evaluating discrete logarithm
/// claims.
pub struct ChallengedGenerator<F: PrimeField, Parameters: DiscreteLogParameters>(
  GenericArray<F, Parameters::ScalarBits>,
);

/// Gadgets for proving the discrete logarithm of points on an elliptic curve defined over the
/// scalar field of the curve of the Bulletproof.
pub trait EcDlogGadgets<C: Ciphersuite> {
  /// Sample a challenge for a series of discrete logarithm claims.
  ///
  /// This must be called after writing the commitments to the transcript.
  ///
  /// The generators are assumed to be non-empty. They are not transcripted. If your generators are
  /// dynamic, they must be properly transcripted into the context.
  ///
  /// May panic/have undefined behavior if an assumption is broken.
  #[allow(clippy::type_complexity)]
  fn discrete_log_challenge<T: Transcript, Parameters: DiscreteLogParameters>(
    &self,
    transcript: &mut T,
    curve: &CurveSpec<C::F>,
    generators: &[GeneratorTable<C::F, Parameters>],
  ) -> (DiscreteLogChallenge<C::F, Parameters>, Vec<ChallengedGenerator<C::F, Parameters>>);

  /// Prove this point has the specified discrete logarithm over the specified generator.
  ///
  /// The discrete logarithm is not validated to be in a canonical form. The only guarantee made on
  /// it is that it's a consistent representation of _a_ discrete logarithm (reuse won't enable
  /// re-interpretation as a distinct discrete logarithm).
  ///
  /// This does ensure the point is on-curve.
  ///
  /// This MUST only be called with `Variable`s present within commitments.
  ///
  /// May panic/have undefined behavior if an assumption is broken, or if passed an invalid
  /// witness.
  fn discrete_log<Parameters: DiscreteLogParameters>(
    &mut self,
    curve: &CurveSpec<C::F>,
    point: PointWithDlog<Parameters>,
    challenge: &DiscreteLogChallenge<C::F, Parameters>,
    challenged_generator: &ChallengedGenerator<C::F, Parameters>,
  ) -> OnCurve;
}

impl<C: Ciphersuite> EcDlogGadgets<C> for Circuit<C> {
  // This is part of `DiscreteLog` from `Discrete Log Proof`, specifically, the challenges and
  // the calculations dependent solely on them
  fn discrete_log_challenge<T: Transcript, Parameters: DiscreteLogParameters>(
    &self,
    transcript: &mut T,
    curve: &CurveSpec<C::F>,
    generators: &[GeneratorTable<C::F, Parameters>],
  ) -> (DiscreteLogChallenge<C::F, Parameters>, Vec<ChallengedGenerator<C::F, Parameters>>) {
    // Get the challenge points
    // TODO: Implement a proper hash to curve
    let (c0_x, c0_y) = loop {
      let c0_x: C::F = transcript.challenge();
      let Some(c0_y) =
        Option::<C::F>::from(((c0_x.square() * c0_x) + (curve.a * c0_x) + curve.b).sqrt())
      else {
        continue;
      };
      // Takes the even y coordinate as to not be dependent on whatever root the above sqrt
      // happens to returns
      // TODO: Randomly select which to take
      break (c0_x, if bool::from(c0_y.is_odd()) { -c0_y } else { c0_y });
    };
    let (c1_x, c1_y) = loop {
      let c1_x: C::F = transcript.challenge();
      let Some(c1_y) =
        Option::<C::F>::from(((c1_x.square() * c1_x) + (curve.a * c1_x) + curve.b).sqrt())
      else {
        continue;
      };
      break (c1_x, if bool::from(c1_y.is_odd()) { -c1_y } else { c1_y });
    };

    // mmadd-1998-cmo
    fn incomplete_add<F: PrimeField>(x1: F, y1: F, x2: F, y2: F) -> Option<(F, F)> {
      if x1 == x2 {
        None?
      }

      let u = y2 - y1;
      let uu = u * u;
      let v = x2 - x1;
      let vv = v * v;
      let vvv = v * vv;
      let r = vv * x1;
      let a = uu - vvv - r.double();
      let x3 = v * a;
      let y3 = (u * (r - a)) - (vvv * y1);
      let z3 = vvv;

      // Normalize from XYZ to XY
      let z3_inv = Option::<F>::from(z3.invert())?;
      let x3 = x3 * z3_inv;
      let y3 = y3 * z3_inv;

      Some((x3, y3))
    }

    let (c2_x, c2_y) = incomplete_add::<C::F>(c0_x, c0_y, c1_x, c1_y)
      .expect("randomly selected points shared an x coordinate");
    // We want C0, C1, C2 = -(C0 + C1)
    let c2_y = -c2_y;

    // Calculate the slope and intercept
    // Safe invert as these x coordinates must be distinct due to passing the above incomplete_add
    let slope = (c1_y - c0_y) * (c1_x - c0_x).invert().unwrap();
    let intercept = c0_y - (slope * c0_x);

    // Calculate the inversions for 2 c_y (for each c) and all of the challenged generators
    let mut inversions = vec![C::F::ZERO; 3 + (generators.len() * Parameters::ScalarBits::USIZE)];

    // Needed for the left-hand side eval
    {
      inversions[0] = c0_y.double();
      inversions[1] = c1_y.double();
      inversions[2] = c2_y.double();
    }

    // Perform the inversions for the generators
    for (i, generator) in generators.iter().enumerate() {
      // Needed for the right-hand side eval
      for (j, generator) in generator.0.iter().enumerate() {
        // `DiscreteLog` has weights of `(mu - (G_i.y + (slope * G_i.x)))**-1` in its last line
        inversions[3 + (i * Parameters::ScalarBits::USIZE) + j] =
          intercept - (generator.1 - (slope * generator.0));
      }
    }
    for challenge_inversion in &inversions {
      // This should be unreachable barring negligible probability
      if challenge_inversion.is_zero().into() {
        panic!("trying to invert 0");
      }
    }
    let mut scratch = vec![C::F::ZERO; inversions.len()];
    let _ = BatchInverter::invert_with_external_scratch(&mut inversions, &mut scratch);

    let mut inversions = inversions.into_iter();
    let inv_c0_two_y = inversions.next().unwrap();
    let inv_c1_two_y = inversions.next().unwrap();
    let inv_c2_two_y = inversions.next().unwrap();

    let c0 = ChallengePoint::new(curve, slope, c0_x, c0_y, inv_c0_two_y);
    let c1 = ChallengePoint::new(curve, slope, c1_x, c1_y, inv_c1_two_y);
    let c2 = ChallengePoint::new(curve, slope, c2_x, c2_y, inv_c2_two_y);

    // Fill in the inverted values
    let mut challenged_generators = Vec::with_capacity(generators.len());
    for _ in 0 .. generators.len() {
      let mut challenged_generator = GenericArray::default();
      for i in 0 .. Parameters::ScalarBits::USIZE {
        challenged_generator[i] = inversions.next().unwrap();
      }
      challenged_generators.push(ChallengedGenerator(challenged_generator));
    }

    (DiscreteLogChallenge { c0, c1, c2, slope, intercept }, challenged_generators)
  }

  // `DiscreteLog` from `Discrete Log Proof`
  fn discrete_log<Parameters: DiscreteLogParameters>(
    &mut self,
    curve: &CurveSpec<C::F>,
    point: PointWithDlog<Parameters>,
    challenge: &DiscreteLogChallenge<C::F, Parameters>,
    challenged_generator: &ChallengedGenerator<C::F, Parameters>,
  ) -> OnCurve {
    let PointWithDlog { divisor, dlog, point } = point;

    // Ensure this is being safely called
    let arg_iter = [point.0, point.1, divisor.y, divisor.zero];
    let arg_iter = arg_iter.iter().chain(divisor.yx.iter());
    let arg_iter = arg_iter.chain(divisor.x_from_power_of_2.iter());
    let arg_iter = arg_iter.chain(dlog.iter());
    for variable in arg_iter {
      debug_assert!(
        matches!(variable, Variable::CG { .. } | Variable::CH { .. } | Variable::V(_)),
        "discrete log proofs requires all arguments belong to commitments",
      );
    }

    // Check the point is on curve
    let point = self.on_curve(curve, point);

    // The challenge has already been sampled so those lines aren't necessary

    // lhs from the paper, evaluating the divisor
    let lhs_eval = LinComb::from(divisor_challenge_eval(self, &divisor, &challenge.c0)) +
      &LinComb::from(divisor_challenge_eval(self, &divisor, &challenge.c1)) +
      &LinComb::from(divisor_challenge_eval(self, &divisor, &challenge.c2));

    // Interpolate the doublings of the generator
    let mut rhs_eval = LinComb::empty();
    // We call this `bit` yet it's not constrained to being a bit
    // It's presumed to be yet may be malleated
    for (bit, weight) in dlog.into_iter().zip(&challenged_generator.0) {
      rhs_eval = rhs_eval.term(*weight, bit);
    }

    // Interpolate the output point
    // intercept - (y - (slope * x))
    // intercept - y + (slope * x)
    // -y + (slope * x) + intercept
    // EXCEPT the output point we're proving the discrete log for isn't the one interpolated
    // Its negative is, so -y becomes y
    // y + (slope * x) + intercept
    let output_interpolation = LinComb::empty()
      .constant(challenge.intercept)
      .term(C::F::ONE, point.y)
      .term(challenge.slope, point.x);
    let output_interpolation_eval = self.eval(&output_interpolation);
    let (_output_interpolation, inverse) =
      self.inverse(Some(output_interpolation), output_interpolation_eval);
    rhs_eval = rhs_eval.term(C::F::ONE, inverse);

    self.equality(lhs_eval, &rhs_eval);

    point
  }
}
