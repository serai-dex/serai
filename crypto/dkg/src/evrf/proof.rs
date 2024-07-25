use subtle::*;
use zeroize::{Zeroize, Zeroizing};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

use blake2::{Digest, Blake2s256};
use ciphersuite::{
  group::{
    ff::{Field, PrimeField, PrimeFieldBits},
    Group, GroupEncoding,
  },
  Ciphersuite,
};

use generalized_bulletproofs::{
  *,
  transcript::{Transcript as ProverTranscript, VerifierTranscript},
  arithmetic_circuit_proof::*,
};
use generalized_bulletproofs_circuit_abstraction::*;

use ec_divisors::{DivisorCurve, new_divisor};
use generalized_bulletproofs_ec_gadgets::*;

#[cfg(test)]
mod tests;

/*
  The following circuit has two roles.

  1) Generating every coefficient used in the DKG, per the eVRF paper, using the fixed eVRF key.

*/

/// A curve to perform the eVRF with.
pub trait EvrfCurve: Ciphersuite {
  type EmbeddedCurve: Ciphersuite;
  type EmbeddedCurveParameters: DiscreteLogParameters;
}

/// The result of proving for an eVRF.
pub(crate) struct EvrfProveResult<C: Ciphersuite> {
  pub(crate) encrypted_scalars: Vec<C::F>,
  pub(crate) proof: Vec<u8>,
}

/// A struct to prove/verify eVRFs with.
pub(crate) struct Evrf;
impl Evrf {
  fn transcript_to_points<C: Ciphersuite>(seed: [u8; 32], quantity: usize) -> Vec<C::G> {
    // We need to do two Diffie-Hellman's per point in order to achieve an unbiased result
    let quantity = 2 * quantity;

    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut res = Vec::with_capacity(quantity);
    while res.len() < quantity {
      let mut repr = <C::G as GroupEncoding>::Repr::default();
      rng.fill_bytes(repr.as_mut());
      if let Ok(point) = C::read_G(&mut repr.as_ref()) {
        res.push(point);
      }
    }
    res
  }

  fn point_with_dlogs<Parameters: DiscreteLogParameters>(
    quantity: usize,
    generators_to_use: usize,
  ) -> Vec<PointWithDlog<Parameters>> {
    let quantity = 2 * quantity;

    fn read_one_from_tape(generators_to_use: usize, start: &mut usize) -> Variable {
      let commitment = *start / (2 * generators_to_use);
      let index = *start % generators_to_use;
      let res = if (*start / generators_to_use) % 2 == 0 {
        Variable::CG { commitment, index }
      } else {
        Variable::CH { commitment, index }
      };
      *start += 1;
      res
    }
    fn read_from_tape<N: ArrayLength>(
      generators_to_use: usize,
      start: &mut usize,
    ) -> GenericArray<Variable, N> {
      let mut buf = Vec::with_capacity(N::USIZE);
      for _ in 0 .. N::USIZE {
        buf.push(read_one_from_tape(generators_to_use, start));
      }
      GenericArray::from_slice(&buf).clone()
    }

    // We define a serialized tape of the discrete logarithm, then for each divisor/point:
    //   zero, x**i, y x**i, y, x_coord, y_coord
    // We then chunk that into vector commitments
    // Here, we take the assumed layout and generate the expected `Variable`s for this layout
    let mut start = 0;

    let dlog = read_from_tape(generators_to_use, &mut start);

    let mut res = Vec::with_capacity(quantity + 1);
    let mut read_point_with_dlog = || {
      let zero = read_one_from_tape(generators_to_use, &mut start);
      let x_from_power_of_2 = read_from_tape(generators_to_use, &mut start);
      let yx = read_from_tape(generators_to_use, &mut start);
      let y = read_one_from_tape(generators_to_use, &mut start);
      let divisor = Divisor { zero, x_from_power_of_2, yx, y };

      let point = (
        read_one_from_tape(generators_to_use, &mut start),
        read_one_from_tape(generators_to_use, &mut start),
      );

      res.push(PointWithDlog { dlog: dlog.clone(), divisor, point });
    };

    for _ in 0 .. quantity {
      // One for each DH proven
      read_point_with_dlog();
    }
    // And one more for the proof this is the discrete log of the public key
    read_point_with_dlog();
    res
  }

  fn muls_and_generators_to_use(quantity: usize) -> (usize, usize) {
    let expected_muls = 7 * (1 + (2 * quantity));
    let generators_to_use = {
      let mut padded_pow_of_2 = 1;
      while padded_pow_of_2 < expected_muls {
        padded_pow_of_2 <<= 1;
      }
      // This may as small as 16, which would create an excessive amount of vector commitments
      // We set a floor of 1024 rows for bandwidth reasons
      padded_pow_of_2.max(1024)
    };
    (expected_muls, generators_to_use)
  }

  fn circuit<C: EvrfCurve>(
    curve_spec: &CurveSpec<C::F>,
    evrf_public_key: (C::F, C::F),
    quantity: usize,
    generator_tables: &[GeneratorTable<C::F, C::EmbeddedCurveParameters>],
    circuit: &mut Circuit<C>,
    transcript: &mut impl Transcript,
  ) {
    let (expected_muls, generators_to_use) = Self::muls_and_generators_to_use(quantity);
    let (challenge, challenged_generators) =
      circuit.discrete_log_challenge(transcript, curve_spec, generator_tables);

    let mut point_with_dlogs =
      Self::point_with_dlogs::<C::EmbeddedCurveParameters>(quantity, generators_to_use).into_iter();

    // Verify the DLog claims for the sampled points
    for (i, pair) in challenged_generators.chunks(2).take(quantity).enumerate() {
      let mut lincomb = LinComb::empty();
      debug_assert_eq!(pair.len(), 2);
      for challenged_generator in pair {
        let point = circuit.discrete_log(
          curve_spec,
          point_with_dlogs.next().unwrap(),
          &challenge,
          challenged_generator,
        );
        // For each point in this pair, add its x coordinate to a lincomb
        lincomb = lincomb.term(C::F::ONE, point.x());
      }
      // Constrain the sum of the two x coordinates to be equal to the value in the Pedersen
      // commitment
      circuit.equality(lincomb, &LinComb::from(Variable::V(i)));
    }

    let point = circuit.discrete_log(
      curve_spec,
      point_with_dlogs.next().unwrap(),
      &challenge,
      challenged_generators.last().unwrap(),
    );
    circuit.equality(LinComb::from(point.x()), &LinComb::empty().constant(evrf_public_key.0));
    circuit.equality(LinComb::from(point.y()), &LinComb::empty().constant(evrf_public_key.1));

    debug_assert_eq!(expected_muls, circuit.muls());
    debug_assert!(point_with_dlogs.next().is_none());
  }

  /// Prove a point on an elliptic curve had its discrete logarithm generated via an eVRF.
  pub(crate) fn prove<C: EvrfCurve>(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    evrf_private_key: Zeroizing<<<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F>,
    invocation: [u8; 32],
    quantity: usize,
  ) -> Result<EvrfProveResult<C>, AcError>
  where
    <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G:
      DivisorCurve<FieldElement = <C as Ciphersuite>::F>,
  {
    let curve_spec = CurveSpec {
      a: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G::a(),
      b: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G::b(),
    };

    // Combine the invocation and the public key into a transcript
    let transcript = Blake2s256::digest(
      [
        invocation.as_slice(),
        (<<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator() * *evrf_private_key)
          .to_bytes()
          .as_ref(),
      ]
      .concat(),
    )
    .into();

    let points = Self::transcript_to_points::<C::EmbeddedCurve>(transcript, quantity);

    let num_bits: u32 = <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F::NUM_BITS;

    // Obtain the bits of the private key
    let mut sum_of_coefficients: u32 = 0;
    let mut dlog = vec![<C as Ciphersuite>::F::ZERO; num_bits as usize];
    for (i, bit) in evrf_private_key.to_le_bits().into_iter().take(num_bits as usize).enumerate() {
      let bit = Choice::from(u8::from(bit));
      dlog[i] =
        <_>::conditional_select(&<C as Ciphersuite>::F::ZERO, &<C as Ciphersuite>::F::ONE, bit);
      sum_of_coefficients += u32::conditional_select(&0, &1, bit);
    }

    /*
      Now that we have the discrete logarithm as the coefficients 0/1 for a polynomial of 2**i, we
      want to malleate it such that the sum of its coefficients is NUM_BITS. The divisor
      calculcation is a non-trivial amount of work and would be extremely vulnerable to timing
      attacks without such efforts.

      We find the highest non-0 coefficient, decrement it, and increase the prior coefficient by 2.
      This increase the sum of the coefficients by 1.
    */
    let two = <C as Ciphersuite>::F::ONE.double();
    for _ in 0 .. num_bits {
      // Find the highest coefficient currently non-zero
      let mut h = 1u32;
      // The value of this highest coefficient, and the coefficient prior to it
      let mut h_value = dlog[h as usize];
      let mut h_prior_value = dlog[(h as usize) - 1];

      // TODO: Squash the following two loops by iterating from the top bit to the bottom bit

      let mut prior_scalar = dlog[(h as usize) - 1];
      for (i, scalar) in dlog.iter().enumerate().skip(h as usize) {
        let is_zero = <C as Ciphersuite>::F::ZERO.ct_eq(scalar);

        // Set `h_*` if this value is non-0
        h = u32::conditional_select(&h, &(i as u32), !is_zero);
        h_value = <C as Ciphersuite>::F::conditional_select(&h_value, scalar, !is_zero);
        h_prior_value =
          <C as Ciphersuite>::F::conditional_select(&h_prior_value, &prior_scalar, !is_zero);

        // Update prior_scalar
        prior_scalar = *scalar;
      }

      // We should not have selected a value equivalent to 0
      // TODO: Ban evrf keys < NUM_BITS and accordingly unable to be so coerced
      // TODO: Preprocess this decomposition of the eVRF key?
      assert!(!bool::from(h_value.ct_eq(&<C as Ciphersuite>::F::ZERO)));

      // Update h_value, h_prior_value as necessary
      h_value -= <C as Ciphersuite>::F::ONE;
      h_prior_value += two;

      // Now, set these values if we should
      let should_set = !sum_of_coefficients.ct_eq(&num_bits);
      sum_of_coefficients += u32::conditional_select(&0, &1, should_set);
      for (i, scalar) in dlog.iter_mut().enumerate() {
        let this_is_prior = (i as u32).ct_eq(&(h - 1));
        let this_is_high = (i as u32).ct_eq(&h);

        *scalar = <_>::conditional_select(scalar, &h_prior_value, should_set & this_is_prior);
        *scalar = <_>::conditional_select(scalar, &h_value, should_set & this_is_high);
      }
    }
    debug_assert!(bool::from(
      dlog
        .iter()
        .sum::<<C as Ciphersuite>::F>()
        .ct_eq(&<C as Ciphersuite>::F::from(u64::from(num_bits)))
    ));

    // A tape of the discrete logarithm, then [zero, x**i, y x**i, y, x_coord, y_coord]
    let mut vector_commitment_tape = vec![];

    // Start by pushing the discrete logarithm onto the tape
    for coefficient in &dlog {
      vector_commitment_tape.push(*coefficient);
    }

    let mut generator_tables = Vec::with_capacity(1 + (2 * quantity));

    // A function to calculate a divisor and push it onto the tape
    // This defines a vec, divisor_points, outside of the fn to reuse its allocation
    let mut divisor_points = Vec::with_capacity((num_bits as usize) + 1);
    let mut divisor = |mut generator: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G| {
      {
        let (x, y) = <C::EmbeddedCurve as Ciphersuite>::G::to_xy(generator).unwrap();
        generator_tables.push(GeneratorTable::new(&curve_spec, x, y));
      }

      let dh = generator * *evrf_private_key;
      {
        for coefficient in &dlog {
          let mut coefficient = *coefficient;
          while coefficient != <C as Ciphersuite>::F::ZERO {
            coefficient -= <C as Ciphersuite>::F::ONE;
            divisor_points.push(generator);
          }
          generator = generator.double();
        }
      }
      divisor_points.push(-dh);
      let mut divisor = new_divisor(&divisor_points).unwrap().normalize_x_coefficient();
      divisor_points.zeroize();

      vector_commitment_tape.push(divisor.zero_coefficient);

      for coefficient in divisor.x_coefficients.iter().skip(1) {
        vector_commitment_tape.push(*coefficient);
      }
      for _ in divisor.x_coefficients.len() ..
        <C::EmbeddedCurveParameters as DiscreteLogParameters>::XCoefficientsMinusOne::USIZE
      {
        vector_commitment_tape.push(<C as Ciphersuite>::F::ZERO);
      }

      for coefficient in divisor.yx_coefficients.first().unwrap_or(&vec![]) {
        vector_commitment_tape.push(*coefficient);
      }
      for _ in divisor.yx_coefficients.first().unwrap_or(&vec![]).len() ..
        <C::EmbeddedCurveParameters as DiscreteLogParameters>::YxCoefficients::USIZE
      {
        vector_commitment_tape.push(<C as Ciphersuite>::F::ZERO);
      }

      vector_commitment_tape
        .push(divisor.y_coefficients.first().cloned().unwrap_or(<C as Ciphersuite>::F::ZERO));

      divisor.zeroize();
      drop(divisor);

      let (x, y) = <C::EmbeddedCurve as Ciphersuite>::G::to_xy(dh).unwrap();
      vector_commitment_tape.push(x);
      vector_commitment_tape.push(y);

      (x, y)
    };

    // Push a divisor for each point we use in the eVRF
    let mut scalars = Vec::with_capacity(quantity);
    for pair in points.chunks(2) {
      let mut res = Zeroizing::new(C::F::ZERO);
      for point in pair {
        let (dh_x, _) = divisor(*point);
        *res += dh_x;
      }
      scalars.push(res);
    }
    debug_assert_eq!(scalars.len(), quantity);

    // Also push a divisor for proving that we're using the correct scalar
    let evrf_public_key = divisor(<<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator());

    dlog.zeroize();
    drop(dlog);

    // Now that we have the vector commitment tape, chunk it
    let (_, generators_to_use) = Self::muls_and_generators_to_use(quantity);

    let mut vector_commitments =
      Vec::with_capacity(vector_commitment_tape.len().div_ceil(generators_to_use));
    for chunk in vector_commitment_tape.chunks(generators_to_use * 2) {
      let g_values = chunk[.. generators_to_use].to_vec().into();
      let h_values = chunk[generators_to_use ..].to_vec().into();
      vector_commitments.push(PedersenVectorCommitment {
        g_values,
        h_values,
        mask: C::F::random(&mut *rng),
      });
    }

    vector_commitment_tape.zeroize();
    drop(vector_commitment_tape);

    let mut commitments = Vec::with_capacity(quantity);
    for scalar in &scalars {
      commitments.push(PedersenCommitment { value: **scalar, mask: C::F::random(&mut *rng) });
    }

    let mut transcript = ProverTranscript::new(transcript);
    let commited_commitments = transcript.write_commitments(
      vector_commitments
        .iter()
        .map(|commitment| {
          commitment
            .commit(generators.g_bold_slice(), generators.h_bold_slice(), generators.h())
            .ok_or(AcError::NotEnoughGenerators)
        })
        .collect::<Result<_, _>>()?,
      commitments
        .iter()
        .map(|commitment| commitment.commit(generators.g(), generators.h()))
        .collect(),
    );

    let mut circuit = Circuit::prove(vector_commitments, commitments.clone());
    Self::circuit::<C>(
      &curve_spec,
      evrf_public_key,
      quantity,
      &generator_tables,
      &mut circuit,
      &mut transcript,
    );

    let (statement, Some(witness)) = circuit
      .statement(
        generators.reduce(generators_to_use).ok_or(AcError::NotEnoughGenerators)?,
        commited_commitments,
      )
      .unwrap()
    else {
      panic!("proving yet wasn't yielded the witness");
    };
    statement.prove(&mut *rng, &mut transcript, witness).unwrap();

    // Push the reveal onto the transcript
    for scalar in &scalars {
      transcript.push_point(generators.g() * **scalar);
    }

    // Define a weight to aggregate the commitments with
    let mut agg_weights = Vec::with_capacity(quantity);
    agg_weights.push(C::F::ONE);
    while agg_weights.len() < quantity {
      agg_weights.push(transcript.challenge::<C::F>());
    }
    let mut x = commitments
      .iter()
      .zip(&agg_weights)
      .map(|(commitment, weight)| commitment.mask * *weight)
      .sum::<C::F>();

    // Do a Schnorr PoK for the randomness of the aggregated Pedersen commitment
    let mut r = C::F::random(&mut *rng);
    transcript.push_point(generators.h() * r);
    let c = transcript.challenge::<C::F>();
    transcript.push_scalar(r + (c * x));
    r.zeroize();
    x.zeroize();

    Ok(EvrfProveResult { scalars, proof: transcript.complete() })
  }

  // TODO: Dedicated error
  /// Verify an eVRF proof, returning the commitments output.
  pub(crate) fn verify<C: EvrfCurve>(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    verifier: &mut BatchVerifier<C>,
    evrf_public_key: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G,
    invocation: [u8; 32],
    quantity: usize,
    proof: &[u8],
  ) -> Result<Vec<C::G>, ()>
  where
    <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G:
      DivisorCurve<FieldElement = <C as Ciphersuite>::F>,
  {
    let curve_spec = CurveSpec {
      a: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G::a(),
      b: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G::b(),
    };

    let transcript =
      Blake2s256::digest([invocation.as_slice(), evrf_public_key.to_bytes().as_ref()].concat())
        .into();

    let points = Self::transcript_to_points::<C::EmbeddedCurve>(transcript, quantity);
    let mut generator_tables = Vec::with_capacity(1 + (2 * quantity));

    for generator in points {
      let (x, y) = <C::EmbeddedCurve as Ciphersuite>::G::to_xy(generator).unwrap();
      generator_tables.push(GeneratorTable::new(&curve_spec, x, y));
    }
    {
      let (x, y) =
        <C::EmbeddedCurve as Ciphersuite>::G::to_xy(<C::EmbeddedCurve as Ciphersuite>::generator())
          .unwrap();
      generator_tables.push(GeneratorTable::new(&curve_spec, x, y));
    }

    let (_, generators_to_use) = Self::muls_and_generators_to_use(quantity);

    let mut transcript = VerifierTranscript::new(transcript, proof);

    let divisor_len = 1 +
      <C::EmbeddedCurveParameters as DiscreteLogParameters>::XCoefficientsMinusOne::USIZE +
      <C::EmbeddedCurveParameters as DiscreteLogParameters>::YxCoefficients::USIZE +
      1;
    let dlog_proof_len = divisor_len + 2;
    let vcs = (<C::EmbeddedCurveParameters as DiscreteLogParameters>::ScalarBits::USIZE +
      ((1 + (2 * quantity)) * dlog_proof_len))
      .div_ceil(2 * generators_to_use);

    let all_commitments = transcript.read_commitments(vcs, quantity).map_err(|_| ())?;
    let commitments = all_commitments.V().to_vec();

    let mut circuit = Circuit::verify();
    Self::circuit::<C>(
      &curve_spec,
      // TODO: Use a better error here
      <C::EmbeddedCurve as Ciphersuite>::G::to_xy(evrf_public_key).ok_or(())?,
      quantity,
      &generator_tables,
      &mut circuit,
      &mut transcript,
    );

    let (statement, None) =
      circuit.statement(generators.reduce(generators_to_use).ok_or(())?, all_commitments).unwrap()
    else {
      panic!("verifying yet was yielded a witness");
    };

    statement.verify(rng, verifier, &mut transcript).map_err(|_| ())?;

    // Read the unblinded public keys
    let mut res = Vec::with_capacity(quantity);
    for _ in 0 .. quantity {
      res.push(transcript.read_point::<C>().map_err(|_| ())?);
    }

    let mut agg_weights = Vec::with_capacity(quantity);
    agg_weights.push(C::F::ONE);
    while agg_weights.len() < quantity {
      agg_weights.push(transcript.challenge::<C::F>());
    }

    let sum_points =
      res.iter().zip(&agg_weights).map(|(point, weight)| *point * *weight).sum::<C::G>();
    let sum_commitments =
      commitments.into_iter().zip(agg_weights).map(|(point, weight)| point * weight).sum::<C::G>();
    #[allow(non_snake_case)]
    let A = sum_commitments - sum_points;

    #[allow(non_snake_case)]
    let R = transcript.read_point::<C>().map_err(|_| ())?;
    let c = transcript.challenge::<C::F>();
    let s = transcript.read_scalar::<C>().map_err(|_| ())?;

    // Doesn't batch verify this as we can't access the internals of the GBP batch verifier
    if (R + (A * c)) != (generators.h() * s) {
      Err(())?;
    }

    if !transcript.complete().is_empty() {
      Err(())?
    };

    Ok(res)
  }
}
