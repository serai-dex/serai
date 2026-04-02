use core::{marker::PhantomData, ops::Deref as _, fmt};
use std_shims::prelude::*;

use zeroize::Zeroizing;

use rand_core::{RngCore, CryptoRng, SeedableRng as _};
use rand_chacha::ChaCha20Rng;

use ciphersuite::{group::ff::Field as _, WrappedGroup};

use generalized_bulletproofs::{
  Generators, BatchVerifier, PedersenCommitment, PedersenVectorCommitment,
  transcript::{Transcript as ProverTranscript, VerifierTranscript},
  arithmetic_circuit_proof::*,
};
use generalized_bulletproofs_circuit_abstraction::{Transcript, Circuit as BpCircuit};

use ec_divisors::{DivisorCurve, ScalarDecomposition};
use generalized_bulletproofs_ec_gadgets::{
  CurveSpec, DiscreteLogChallenge, ChallengedGenerator, EcDlogGadgets as _,
};

use crate::Curves;

mod tape;
use tape::*;

type EmbeddedPoint<C> = (
  <<<C as Curves>::EmbeddedCurve as WrappedGroup>::G as DivisorCurve>::FieldElement,
  <<<C as Curves>::EmbeddedCurve as WrappedGroup>::G as DivisorCurve>::FieldElement,
);

#[expect(non_snake_case)]
struct Circuit<
  'circuit,
  C: Curves,
  CG: Iterator<
    Item = ChallengedGenerator<<C::ToweringCurve as WrappedGroup>::F, C::EmbeddedCurveParameters>,
  >,
> {
  curve_spec:
    &'circuit CurveSpec<<<C::EmbeddedCurve as WrappedGroup>::G as DivisorCurve>::FieldElement>,
  circuit: &'circuit mut BpCircuit<C::ToweringCurve>,
  challenge:
    DiscreteLogChallenge<<C::ToweringCurve as WrappedGroup>::F, C::EmbeddedCurveParameters>,
  challenged_G:
    ChallengedGenerator<<C::ToweringCurve as WrappedGroup>::F, C::EmbeddedCurveParameters>,
  challenged_generators: &'circuit mut CG,
  tape: Tape,
  pedersen_commitment_tape: PedersenCommitmentTape,
}

impl<
    C: Curves,
    CG: Iterator<
      Item = ChallengedGenerator<<C::ToweringCurve as WrappedGroup>::F, C::EmbeddedCurveParameters>,
    >,
  > Circuit<'_, C, CG>
{
  /// Generate coefficients for secret-sharing via an eVRF.
  ///
  /// This follows the methodology of Protocol 5 from the
  /// [eVRF paper](https://eprint.iacr.org/2024/397.pdf).
  fn coefficients(&mut self, evrf_public_key: EmbeddedPoint<C>, coefficients: usize) {
    /*
      Read the opening of the prover's eVRF public key, along with all the proofs for the eVRF.
      Each invocation of the eVRF requires performing _two_ Diffie-Hellmans against
      uniformly-sampled points.
    */
    let mut point_with_dlogs = self.tape.read_points_with_common_dlog::<C>(1 + (2 * coefficients));

    // Assert this discrete logarithm opens the prover's public key
    let point = self.circuit.discrete_log(
      self.curve_spec,
      point_with_dlogs.next().unwrap(),
      &self.challenge,
      &self.challenged_G,
    );
    self.circuit.equality(LinComb::from(point.x()), &LinComb::empty().constant(evrf_public_key.0));
    self.circuit.equality(LinComb::from(point.y()), &LinComb::empty().constant(evrf_public_key.1));

    // Verify the eVRF invocations
    for _ in 0 .. coefficients {
      let mut lincomb = LinComb::empty();
      for challenged_generator in
        [self.challenged_generators.next().unwrap(), self.challenged_generators.next().unwrap()]
      {
        let point = self.circuit.discrete_log(
          self.curve_spec,
          point_with_dlogs.next().unwrap(),
          &self.challenge,
          &challenged_generator,
        );
        lincomb = lincomb.term(<C::ToweringCurve as WrappedGroup>::F::ONE, point.x());
      }
      /*
        Constrain the sum of the two `x` coordinates to be equal to the value committed to in a
        Pedersen commitment
      */
      self.circuit.equality(
        lincomb,
        &LinComb::from(self.pedersen_commitment_tape.allocate_pedersen_commitment()),
      );
    }
    debug_assert!(point_with_dlogs.next().is_none());
  }

  /// Sample an encryption key, proving it's correctly-formed and committed to within a Pedersen
  /// commitment.
  fn verifiable_encryption(&mut self, ecdh_commitments: &[EmbeddedPoint<C>; 2]) {
    // Read the public key used for this encryption
    let challenged_public_key = self.challenged_generators.next().unwrap();
    // We perform two separate ECDHs, the sum of their `x` coordinates being our encryption key
    let mut lincomb = LinComb::empty();
    for ecdh_commitment in ecdh_commitments {
      // We open the posted commitment to the ephemeral secret used, and the ECDH value
      let mut point_with_dlogs = self.tape.read_points_with_common_dlog::<C>(2);

      let point = self.circuit.discrete_log(
        self.curve_spec,
        point_with_dlogs.next().unwrap(),
        &self.challenge,
        &self.challenged_G,
      );
      // Ensure this equals the publicly posted commitment
      self
        .circuit
        .equality(LinComb::from(point.x()), &LinComb::empty().constant(ecdh_commitment.0));
      self
        .circuit
        .equality(LinComb::from(point.y()), &LinComb::empty().constant(ecdh_commitment.1));

      let point = self.circuit.discrete_log(
        self.curve_spec,
        point_with_dlogs.next().unwrap(),
        &self.challenge,
        &challenged_public_key,
      );
      lincomb = lincomb.term(<C::ToweringCurve as WrappedGroup>::F::ONE, point.x());
      debug_assert!(point_with_dlogs.next().is_none());
    }

    // Require the encryption mask be successfully commited to within a Pedersen commitment
    self.circuit.equality(
      lincomb,
      &LinComb::from(self.pedersen_commitment_tape.allocate_pedersen_commitment()),
    );
  }
}

/// The result of proving.
pub(super) struct ProveResult<C: Curves> {
  /// The coefficients for use in the DKG.
  pub(super) coefficients: Vec<Zeroizing<<C::ToweringCurve as WrappedGroup>::F>>,
  /// The masks to encrypt secret shares with.
  pub(super) encryption_keys: Vec<Zeroizing<<C::ToweringCurve as WrappedGroup>::F>>,
  /// The proof itself.
  pub(super) proof: Vec<u8>,
}

pub(super) struct Verified<C: Curves> {
  /// The commitments to the coefficients used within the DKG.
  pub(super) coefficients: Vec<<C::ToweringCurve as WrappedGroup>::G>,
  /// The ephemeral public keys to perform ECDHs with
  pub(super) ecdh_commitments: Vec<[<C::EmbeddedCurve as WrappedGroup>::G; 2]>,
  /// The commitments to the masks used to encrypt secret shares with.
  pub(super) encryption_key_commitments: Vec<<C::ToweringCurve as WrappedGroup>::G>,
}

impl<C: Curves> fmt::Debug for Verified<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt.debug_struct("Verified").finish_non_exhaustive()
  }
}

type GeneratorTable<C> = generalized_bulletproofs_ec_gadgets::GeneratorTable<
  <<<C as Curves>::EmbeddedCurve as WrappedGroup>::G as DivisorCurve>::FieldElement,
  <C as Curves>::EmbeddedCurveParameters,
>;

pub(super) struct Proof<C>(PhantomData<C>);
impl<C: Curves> Proof<C> {
  fn discrete_log_claims(coefficients: usize, participants: usize) -> usize {
    /*
      - 1 DLOG to prove the discrete logarithm corresponds to the eVRF public key
      - 2 DLOGs per coefficient in the secret-sharing polynomial
      - 2 DLOGs per each ECDH (one to open the commitment, one for the ECDH itself), with two ECDHs
        for each participant (with the sum of their `x` coordinates being uniform and used as the
        mask)
    */
    const DLOGS_PER_COEFFICIENT: usize = 2;
    const ECDHS_PER_PARTICIPANT: usize = 2;
    const DLOGS_PER_ECDH: usize = 2;
    const DLOGS_PER_PARTICIPANT: usize = ECDHS_PER_PARTICIPANT * DLOGS_PER_ECDH;
    1 + (DLOGS_PER_COEFFICIENT * coefficients) + (DLOGS_PER_PARTICIPANT * participants)
  }

  fn expected_multiplications(coefficients: usize, participants: usize) -> usize {
    const MULS_PER_DLOG: usize = 7;
    MULS_PER_DLOG * Self::discrete_log_claims(coefficients, participants)
  }

  pub(crate) fn generators_to_use(coefficients: usize, participants: usize) -> usize {
    /*
      `expected_multiplications` may be as small as 16, which would create an excessive amount of
      vector commitments (as a vector commitment can only commit to as many variables as we have
      multiplications).

      We require the actual amount of multiplications to be at least 2048 (even though that
      that 'wastes' thousands of multiplications) to ensure the bandwidth usage remains reasonable.
    */
    Self::expected_multiplications(coefficients, participants).next_power_of_two().max(2048)
  }

  fn variables_in_vector_commitments(coefficients: usize, participants: usize) -> usize {
    Tape::variables_for_points_with_common_dlog::<C>(1 + (2 * coefficients)) +
      (participants * 2 * Tape::variables_for_points_with_common_dlog::<C>(2))
  }

  fn circuit(
    curve_spec: &CurveSpec<<<C::EmbeddedCurve as WrappedGroup>::G as DivisorCurve>::FieldElement>,
    evrf_public_key: EmbeddedPoint<C>,
    coefficients: usize,
    ecdh_commitments: &[[EmbeddedPoint<C>; 2]],
    generator_tables: &[&GeneratorTable<C>],
    circuit: &mut BpCircuit<C::ToweringCurve>,
    transcript: &mut impl Transcript,
  ) {
    let participants = ecdh_commitments.len();
    let generators_to_use = Self::generators_to_use(coefficients, participants);

    // Sample the challenge for all the discrete-logarithm claims
    let (challenge, challenged_generators) =
      circuit.discrete_log_challenge(transcript, curve_spec, generator_tables);

    /*
      The generator tables, and the challenged generators, will have the following layout:
      - G
      - Generators for the eVRFs used to sample the coefficients
      - The participants' public keys, used for performing ECDHs with
    */
    let mut challenged_generators = challenged_generators.into_iter();
    #[expect(non_snake_case)]
    let challenged_G = challenged_generators.next().unwrap();

    let tape = Tape::new(generators_to_use);
    let pedersen_commitment_tape = PedersenCommitmentTape::new();

    {
      let mut circuit = Circuit::<C, _> {
        curve_spec,
        circuit,
        challenge,
        challenged_G,
        challenged_generators: &mut challenged_generators,
        tape,
        pedersen_commitment_tape,
      };

      circuit.coefficients(evrf_public_key, coefficients);

      // Now execute the circuit for the ECDHs
      for ecdh_commitments in ecdh_commitments {
        circuit.verifiable_encryption(ecdh_commitments);
      }
    }

    debug_assert_eq!(
      Self::expected_multiplications(coefficients, participants),
      circuit.muls(),
      "unexpected amount of multiplications actually used"
    );
    debug_assert!(
      challenged_generators.next().is_none(),
      "didn't consume all challenged generators"
    );
  }

  /// Sample the points for the eVRF invocations used for the coefficients.
  fn sample_coefficients_evrf_points(
    seed: [u8; 32],
    coefficients: usize,
  ) -> Vec<<C::EmbeddedCurve as WrappedGroup>::G> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let quantity = 2 * coefficients;
    let mut res = Vec::with_capacity(quantity);
    for _ in 0 .. quantity {
      res.push(crate::sample_point::<C::EmbeddedCurve>(&mut rng));
    }
    res
  }

  /// Create the required tables for the generators.
  fn generator_tables(
    coefficients_evrf_points: &[<C::EmbeddedCurve as WrappedGroup>::G],
    participants: &[<<C as Curves>::EmbeddedCurve as WrappedGroup>::G],
  ) -> Vec<GeneratorTable<C>> {
    let curve_spec = CurveSpec {
      a: <<C as Curves>::EmbeddedCurve as WrappedGroup>::G::a(),
      b: <<C as Curves>::EmbeddedCurve as WrappedGroup>::G::b(),
    };

    let mut generator_tables =
      Vec::with_capacity(1 + coefficients_evrf_points.len() + participants.len());
    {
      let (x, y) = <C::EmbeddedCurve as WrappedGroup>::G::to_xy(
        <C::EmbeddedCurve as WrappedGroup>::generator(),
      )
      .unwrap();
      generator_tables.push(GeneratorTable::<C>::new(&curve_spec, x, y));
    }
    for generator in coefficients_evrf_points {
      let (x, y) = <C::EmbeddedCurve as WrappedGroup>::G::to_xy(*generator).unwrap();
      generator_tables.push(GeneratorTable::<C>::new(&curve_spec, x, y));
    }
    for generator in participants {
      let (x, y) = <C::EmbeddedCurve as WrappedGroup>::G::to_xy(*generator).unwrap();
      generator_tables.push(GeneratorTable::<C>::new(&curve_spec, x, y));
    }
    generator_tables
  }

  pub(super) fn prove(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C::ToweringCurve>,
    transcript: [u8; 32],
    coefficients: usize,
    participant_public_keys: &[<<C as Curves>::EmbeddedCurve as WrappedGroup>::G],
    evrf_private_key: &Zeroizing<<<C as Curves>::EmbeddedCurve as WrappedGroup>::F>,
  ) -> Result<ProveResult<C>, AcProveError> {
    let curve_spec = CurveSpec {
      a: <<C as Curves>::EmbeddedCurve as WrappedGroup>::G::a(),
      b: <<C as Curves>::EmbeddedCurve as WrappedGroup>::G::b(),
    };

    let coefficients_evrf_points = Self::sample_coefficients_evrf_points(transcript, coefficients);
    let generator_tables =
      Self::generator_tables(&coefficients_evrf_points, participant_public_keys);

    // Push a discrete logarithm onto the tape
    let discrete_log =
      |vector_commitment_tape: &mut Vec<_>,
       dlog: &ScalarDecomposition<<<C as Curves>::EmbeddedCurve as WrappedGroup>::F>| {
        for coefficient in dlog.decomposition() {
          vector_commitment_tape.push(<_>::from(*coefficient));
        }
      };

    // Push a discrete-log claim onto the tape.
    //
    // Returns the point for which the claim was made.
    let discrete_log_claim =
      |vector_commitment_tape: &mut Vec<_>,
       dlog: &ScalarDecomposition<<<C as Curves>::EmbeddedCurve as WrappedGroup>::F>,
       generator: <<C as Curves>::EmbeddedCurve as WrappedGroup>::G| {
        {
          let divisor =
            Zeroizing::new(dlog.scalar_mul_divisor(generator).normalize_x_coefficient());
          vector_commitment_tape.push(divisor.zero_coefficient);
          for coefficient in divisor.x_coefficients.iter().skip(1) {
            vector_commitment_tape.push(*coefficient);
          }
          for coefficient in divisor.yx_coefficients.first().unwrap_or(&vec![]) {
            vector_commitment_tape.push(*coefficient);
          }
          vector_commitment_tape.push(
            divisor
              .y_coefficients
              .first()
              .copied()
              .unwrap_or(<C::ToweringCurve as WrappedGroup>::F::ZERO),
          );
        }

        let dh = generator * dlog.scalar();
        let (x, y) = <C::EmbeddedCurve as WrappedGroup>::G::to_xy(dh).unwrap();
        vector_commitment_tape.push(x);
        vector_commitment_tape.push(y);
        (dh, (x, y))
      };

    let mut vector_commitment_tape = Zeroizing::new(Vec::with_capacity(
      Self::variables_in_vector_commitments(coefficients, participant_public_keys.len()),
    ));

    // Handle the coefficients
    let mut coefficients = Vec::with_capacity(coefficients);
    let evrf_public_key = {
      let evrf_private_key =
        ScalarDecomposition::<<C::EmbeddedCurve as WrappedGroup>::F>::new(**evrf_private_key)
          .expect("eVRF private key was zero");

      discrete_log(&mut vector_commitment_tape, &evrf_private_key);

      // Push the divisor for proving that we're using the correct scalar
      let (_, evrf_public_key) = discrete_log_claim(
        &mut vector_commitment_tape,
        &evrf_private_key,
        <<C as Curves>::EmbeddedCurve as WrappedGroup>::generator(),
      );

      // Push the divisor for each point we use in the eVRF
      for pair in coefficients_evrf_points.chunks(2) {
        let mut coefficient = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::ZERO);
        for point in pair {
          let (_, (dh_x, _)) =
            discrete_log_claim(&mut vector_commitment_tape, &evrf_private_key, *point);
          *coefficient += dh_x;
        }
        coefficients.push(coefficient);
      }

      evrf_public_key
    };

    // Handle the verifiable encryption
    let mut encryption_keys = Vec::with_capacity(participant_public_keys.len());
    let mut ecdh_commitments = Vec::with_capacity(2 * participant_public_keys.len());
    let mut ecdh_commitments_xy = Vec::with_capacity(participant_public_keys.len());
    for participant_public_key in participant_public_keys {
      let mut ecdh_commitments_xy_i = [(
        <C::ToweringCurve as WrappedGroup>::F::ZERO,
        <C::ToweringCurve as WrappedGroup>::F::ZERO,
      ); 2];
      let mut encryption_key = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::ZERO);
      for ecdh_commitments_xy_i_j_dest in &mut ecdh_commitments_xy_i {
        let mut ecdh_ephemeral_secret;
        loop {
          ecdh_ephemeral_secret =
            Zeroizing::new(<C::EmbeddedCurve as WrappedGroup>::F::random(&mut *rng));
          // 0 would produce the identity, which isn't representable within the discrete-log proof.
          if bool::from(!ecdh_ephemeral_secret.is_zero()) {
            break;
          }
        }

        let ecdh_ephemeral_secret =
          ScalarDecomposition::<<C::EmbeddedCurve as WrappedGroup>::F>::new(*ecdh_ephemeral_secret)
            .expect("ECDH ephemeral secret zero");
        discrete_log(&mut vector_commitment_tape, &ecdh_ephemeral_secret);

        // Push a divisor for proving that we're using the correct scalar for the commitment
        let (ecdh_commitment, ecdh_commitment_xy_i_j) = discrete_log_claim(
          &mut vector_commitment_tape,
          &ecdh_ephemeral_secret,
          <<C as Curves>::EmbeddedCurve as WrappedGroup>::generator(),
        );
        ecdh_commitments.push(ecdh_commitment);
        *ecdh_commitments_xy_i_j_dest = ecdh_commitment_xy_i_j;
        // Push a divisor for the key we're performing the ECDH with
        let (_, (dh_x, _)) = discrete_log_claim(
          &mut vector_commitment_tape,
          &ecdh_ephemeral_secret,
          *participant_public_key,
        );
        *encryption_key += dh_x;
      }
      ecdh_commitments_xy.push(ecdh_commitments_xy_i);
      encryption_keys.push(encryption_key);
    }

    // Convert the vector commitment tape into vector commitments
    let generators_to_use =
      Self::generators_to_use(coefficients.len(), participant_public_keys.len());
    debug_assert_eq!(
      Self::variables_in_vector_commitments(coefficients.len(), participant_public_keys.len()),
      vector_commitment_tape.len()
    );
    let mut vector_commitments =
      Vec::with_capacity(vector_commitment_tape.len().div_ceil(generators_to_use));
    for chunk in vector_commitment_tape.chunks(generators_to_use) {
      vector_commitments.push(PedersenVectorCommitment {
        g_values: chunk.into(),
        mask: <C::ToweringCurve as WrappedGroup>::F::random(&mut *rng),
      });
    }

    // Create the Pedersen commitments
    let mut commitments = Vec::with_capacity(coefficients.len() + participant_public_keys.len());
    for coefficient in &coefficients {
      commitments.push(PedersenCommitment {
        value: **coefficient,
        mask: <C::ToweringCurve as WrappedGroup>::F::random(&mut *rng),
      });
    }
    for enc_mask in &encryption_keys {
      commitments.push(PedersenCommitment {
        value: **enc_mask,
        mask: <C::ToweringCurve as WrappedGroup>::F::random(&mut *rng),
      });
    }

    let mut transcript = ProverTranscript::new(transcript);
    let commited_commitments = transcript.write_commitments(
      vector_commitments
        .iter()
        .map(|commitment| {
          commitment
            .commit(generators.g_bold_slice(), generators.h())
            .ok_or(AcProveError::IncorrectAmountOfGenerators)
        })
        .collect::<Result<_, _>>()?,
      commitments
        .iter()
        .map(|commitment| commitment.commit(generators.g(), generators.h()))
        .collect(),
    );
    for ecdh_commitment in ecdh_commitments {
      transcript.push_point(&ecdh_commitment);
    }

    let mut circuit = BpCircuit::prove(vector_commitments, commitments.clone());
    Self::circuit(
      &curve_spec,
      evrf_public_key,
      coefficients.len(),
      &ecdh_commitments_xy,
      &generator_tables.iter().collect::<Vec<_>>(),
      &mut circuit,
      &mut transcript,
    );

    let (statement, Some(witness)) = circuit
      .statement(
        generators.reduce(generators_to_use).ok_or(AcProveError::IncorrectAmountOfGenerators)?,
        commited_commitments,
      )
      .unwrap()
    else {
      panic!("proving yet wasn't yielded the witness");
    };
    statement.prove(&mut *rng, &mut transcript, witness).unwrap();

    // Push the reveal onto the transcript
    for commitment in &commitments {
      transcript.push_point(&(generators.g() * commitment.value));
    }

    // Prove the openings of the commitments were correct
    let mut x = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::ZERO);
    for commitment in commitments {
      *x += commitment.mask * transcript.challenge::<C::ToweringCurve>();
    }

    // Produce a Schnorr PoK for the weighted-sum of the Pedersen commitments' blinding factors
    let r = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::random(&mut *rng));
    transcript.push_point(&(generators.h() * r.deref()));
    let c = transcript.challenge::<C::ToweringCurve>();
    transcript.push_scalar((c * x.deref()) + r.deref());

    Ok(ProveResult { coefficients, encryption_keys, proof: transcript.complete() })
  }

  #[expect(clippy::too_many_arguments)]
  pub(super) fn verify(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C::ToweringCurve>,
    verifier: &mut BatchVerifier<C::ToweringCurve>,
    transcript: [u8; 32],
    coefficients: usize,
    participant_public_keys: &[<<C as Curves>::EmbeddedCurve as WrappedGroup>::G],
    evrf_public_key: <<C as Curves>::EmbeddedCurve as WrappedGroup>::G,
    proof: &[u8],
  ) -> Result<Verified<C>, ()> {
    let (mut transcript, ecdh_commitments, pedersen_commitments) = {
      let curve_spec = CurveSpec {
        a: <<C as Curves>::EmbeddedCurve as WrappedGroup>::G::a(),
        b: <<C as Curves>::EmbeddedCurve as WrappedGroup>::G::b(),
      };

      let coefficients_evrf_points =
        Self::sample_coefficients_evrf_points(transcript, coefficients);
      let generator_tables =
        Self::generator_tables(&coefficients_evrf_points, participant_public_keys);

      let generators_to_use = Self::generators_to_use(coefficients, participant_public_keys.len());

      let mut transcript = VerifierTranscript::new(transcript, proof);

      let vector_commitments =
        Self::variables_in_vector_commitments(coefficients, participant_public_keys.len())
          .div_ceil(generators_to_use);
      /*
        One commitment is used to commit to each coefficient of the secret-sharing polynomial, and
        one commitment is used to commit to each encryption key used to encrypt a secret share to
        its recipient.
      */
      let pedersen_commitments = coefficients + participant_public_keys.len();
      let all_commitments =
        transcript.read_commitments(vector_commitments, pedersen_commitments).map_err(|_| ())?;
      let pedersen_commitments = all_commitments.V().to_vec();

      // Read the commitments to the ephemeral secrets for the ECDHs
      let mut ecdh_commitments = Vec::with_capacity(participant_public_keys.len());
      let mut ecdh_commitments_xy = Vec::with_capacity(participant_public_keys.len());
      for _ in 0 .. participant_public_keys.len() {
        let ecdh_commitments_i = [
          transcript.read_point::<C::EmbeddedCurve>().map_err(|_| ())?,
          transcript.read_point::<C::EmbeddedCurve>().map_err(|_| ())?,
        ];
        ecdh_commitments.push(ecdh_commitments_i);
        // This inherently bans using the identity point, as it won't have an affine representation
        ecdh_commitments_xy.push([
          <<C::EmbeddedCurve as WrappedGroup>::G as DivisorCurve>::to_xy(ecdh_commitments_i[0])
            .ok_or(())?,
          <<C::EmbeddedCurve as WrappedGroup>::G as DivisorCurve>::to_xy(ecdh_commitments_i[1])
            .ok_or(())?,
        ]);
      }

      let mut circuit = BpCircuit::verify();
      Self::circuit(
        &curve_spec,
        <C::EmbeddedCurve as WrappedGroup>::G::to_xy(evrf_public_key).ok_or(())?,
        coefficients,
        &ecdh_commitments_xy,
        &generator_tables.iter().collect::<Vec<_>>(),
        &mut circuit,
        &mut transcript,
      );

      let (statement, None) = circuit
        .statement(generators.reduce(generators_to_use).ok_or(())?, all_commitments)
        .unwrap()
      else {
        panic!("verifying yet was yielded a witness");
      };

      statement.verify(rng, verifier, &mut transcript).map_err(|_| ())?;

      (transcript, ecdh_commitments, pedersen_commitments)
    };

    // Read the openings for each of the Pedersen commitments
    let mut openings = Vec::with_capacity(pedersen_commitments.len());
    for _ in 0 .. pedersen_commitments.len() {
      openings.push(transcript.read_point::<C::ToweringCurve>().map_err(|_| ())?);
    }

    /*
      Verify the openings of each of the Pedersen commitments.

      We do this via verifying the prover knows an opening of their Pedersen commitment, minus the
      claimed opening, over the blinding generator. For efficiency, we take a random combination of
      all commitments/openings, solely requiring the prover know the single opening for the
      combination.
    */
    {
      let (weighted_sum_commitments, weighted_sum_openings) = {
        let mut weighted_sum_commitments = Vec::with_capacity(pedersen_commitments.len());
        let mut weighted_sum_openings = Vec::with_capacity(pedersen_commitments.len());
        for (pedersen_commitment, opening) in pedersen_commitments.iter().zip(&openings) {
          let weight = transcript.challenge::<C::ToweringCurve>();
          weighted_sum_commitments.push((weight, *pedersen_commitment));
          weighted_sum_openings.push((weight, *opening));
        }
        (
          multiexp::multiexp_vartime(&weighted_sum_commitments),
          multiexp::multiexp_vartime(&weighted_sum_openings),
        )
      };
      #[expect(non_snake_case)]
      let A = weighted_sum_commitments - weighted_sum_openings;

      // Schnorr signature
      #[expect(non_snake_case)]
      let R = transcript.read_point::<C::ToweringCurve>().map_err(|_| ())?;
      let c = transcript.challenge::<C::ToweringCurve>();
      let s = transcript.read_scalar::<C::ToweringCurve>().map_err(|_| ())?;

      // Doesn't batch verify this as we can't access the internals of the GBP batch verifier
      if (R + (A * c)) != (generators.h() * s) {
        Err(())?;
      }
    }

    if !transcript.complete().is_empty() {
      Err(())?;
    }

    let coefficients = openings[.. coefficients].to_vec();
    let encryption_key_commitments = openings[coefficients.len() ..].to_vec();
    Ok(Verified { coefficients, ecdh_commitments, encryption_key_commitments })
  }
}
