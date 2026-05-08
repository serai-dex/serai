use core::{marker::PhantomData, ops::Deref as _, fmt};
use std_shims::prelude::*;

use zeroize::Zeroizing;

use rand_core::{RngCore, CryptoRng, SeedableRng as _};
use rand_chacha::ChaCha20Rng;

use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField},
    GroupEncoding,
  },
  WrappedGroup,
};

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

mod reveal;

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
  ///
  /// This is the fundamental gadget behind this novelty, as detailed in the following documents:
  /// - https://gist.github.com/kayabaNerve/cfbde74b0660dfdf8dd55326d6ec33d7
  /// - https://github.com/serai-dex/serai/blob/next/audits/crypto/dkg/evrf/Security%20Proofs.pdf
  ///
  /// A similar gadget was also detailed in a later publication, https://eprint.iacr.org/2025/1924.
  /// The schemes differ in that ours samples ephemeral scalars to use for the ECDHs, approximate
  /// to ECIES. In contrast, the authors of Golden calculate the ECDH between long-lived public
  /// keys, using the mutually-known ECDH's `x` coordinate as the discrete-logarithm for scaling
  /// two ephemerally-sampled points (the sum of their `x` coordinates forming the encryption key).
  ///
  /// Their scheme requires proving one scalar multiplication of the prover's key, and then three
  /// per other participant (one to prove the calculation of the shared ECDH, one to prove the
  /// calculation of the two ECDHs with ephemerally-sampled points). Our scheme requires proving
  /// four scalar multiplications, the two openings for the commitments to the sampled scalars and
  /// the two ECDHs, before communicating the commitments in question. In that regard, the scheme
  /// presented in Golden can be considered more efficient.
  ///
  /// However, the usage of an `x` coordinate from a single ECDH is not unbiased, and also can't
  /// simply be reduced from a field element into a scalar. Even if one argues the loss of security
  /// negligible (or even irrelevant due to more efficient attacks already known to exist), if the
  /// scheme did use an unbiased discrete-log for the ephemeral ECDHs, it'd presumably need at
  /// least a second static public-key to sample. This still replaces the two at-time-of-DKG
  /// commitments to ephemeral scalars with one additional at-setup commitment and could still be
  /// considered more efficient.
  ///
  /// One other benefit of Golden's design is not sampling ephemeral encryption keys, avoiding
  /// needing to commit to the discrete logarithm of each one.
  ///
  /// While the efficiency is tempting, this maintains use of emphemerally-sampled encryption keys.
  /// In order to consider adopting their clever technique of a static DH used as a discrete-log
  /// for ephemerally-sampled points, we would want to see a proof the static DH's `x` coordinate
  /// is uniform as a discrete logarithm, which it wouldn't be except perhaps for some special
  /// choices of primes. To sketch a modification which would achieve this goal however,
  ///
  /// For an elliptic curve defined over $p$ with order $q$, a generator $G$, and
  /// $(A_1, A_2, B_1, B_2)$ from a setup with the lower-case variants representing their
  /// discrete-logarithms over $G$, we posit
  /// $(a_1 \cdot B_1).x * p + (a_2 \cdot B_2) % q$ to be within $1/((q / 2)^2 / q)$-distance from
  /// uniform of $\mathbb{F}_q$, which is sufficient when $(q / 2)^2 / q$ is greater than or equal
  /// to the security parameter $\kappa$. The exact details would involve an argument that this is
  /// effectively a wide reduction from $p^2$ to $q$ (such as a 512-bit reduction to a 256-bit
  /// prime field), and the distance from uniform modulo $p^2$ is minor (only a few bits).
  ///
  /// We'll also note that the verifiable encryption gadget in Golden does not immediately work
  /// when for a batch, multiple recipients share public keys. The scheme would have to be extended
  /// to also hash the index of the recipient as to avoid sampling the same ephemeral points and
  /// reusing them (a trivial adjustment). Ephemerally-sampled scalars for each recipient do not
  /// have that concern.
  ///
  /// Finally, in our scheme, we'll note one _could_ use ephemerally-sampled scalars _per proof_ to
  /// reduce from four scalar multiplications per-message to just two, achieving greater efficiency
  /// than Golden re: amount of scalar multiplications, but also losing the ability to send to
  /// multiple messages with a single public key. Such a scheme does not immediately have a trivial
  /// adjustment available to restore that functionality, unless one argued that a publicly-derived
  /// tweak of a recipient's key was still usable as if uniformly sampled.
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

const DLOGS_PER_COEFFICIENT: usize = 2;
const DLOGS_PER_ECDH: usize = 2;
const ECDHS_PER_PARTICIPANT: usize = 2;

pub(super) struct Proof<C>(PhantomData<C>);
impl<C: Curves> Proof<C> {
  const fn discrete_log_claims(coefficients: usize, participants: usize) -> usize {
    /*
      - 1 DLOG to prove the discrete logarithm corresponds to the eVRF public key
      - 2 DLOGs per coefficient in the secret-sharing polynomial
      - 2 DLOGs per each ECDH (one to open the commitment, one for the ECDH itself), with two ECDHs
        for each participant (with the sum of their `x` coordinates being uniform and used as the
        mask)
    */
    1 + (DLOGS_PER_COEFFICIENT * coefficients) +
      (DLOGS_PER_ECDH * ECDHS_PER_PARTICIPANT * participants)
  }

  const fn expected_multiplications(coefficients: usize, participants: usize) -> usize {
    const MULS_PER_DLOG: usize = 7;
    MULS_PER_DLOG * Self::discrete_log_claims(coefficients, participants)
  }

  pub(crate) const fn generators_to_use(coefficients: usize, participants: usize) -> usize {
    let muls = Self::expected_multiplications(coefficients, participants).next_power_of_two();
    /*
      `expected_multiplications` may be as small as 16, which would create an excessive amount of
      vector commitments (as a vector commitment can only commit to as many variables as we have
      multiplications).

      We require the actual amount of multiplications to be at least 2048 (even though that
      that 'wastes' thousands of multiplications) to ensure the bandwidth usage remains reasonable.
    */
    if muls < 2048 {
      2048
    } else {
      muls
    }
  }

  fn variables_in_vector_commitments(coefficients: usize, participants: usize) -> usize {
    Tape::variables_for_points_with_common_dlog::<C>(1 + (DLOGS_PER_COEFFICIENT * coefficients)) +
      (participants *
        ECDHS_PER_PARTICIPANT *
        Tape::variables_for_points_with_common_dlog::<C>(DLOGS_PER_ECDH))
  }

  fn vector_commitments(coefficients: usize, participants: usize) -> usize {
    Self::variables_in_vector_commitments(coefficients, participants)
      .div_ceil(Self::generators_to_use(coefficients, participants))
  }

  // TODO: Upstream this to `generalized-bulletproofs`?
  pub(crate) fn transcript_len(coefficients: usize, participants: usize) -> usize {
    // `AI, AO, AS`
    let mut group_elements = 3;
    // `tau_x, u, t_caret, a, b`
    let mut scalar_eleents = 5;
    // IPA rows
    group_elements +=
      2 * usize::try_from(Self::generators_to_use(coefficients, participants).ilog2()).unwrap();

    // Vector commitments
    group_elements += {
      let vector_commitments = Self::vector_commitments(coefficients, participants);
      let ni = 2 + (2 * vector_commitments);
      let l_r_poly_len = 1 + ni + 1;
      let t_poly_len = (2 * l_r_poly_len) - 1;
      let t_commitments = t_poly_len - (ni / 2) - 1;
      vector_commitments + t_commitments
    };

    // Commitments (to the coefficients, encrypted secret shares)
    let commitments = coefficients + participants;
    group_elements += commitments;

    // Commitments to the ephemeral scalars used for the ECDHs
    group_elements += 2 * participants;

    // Opening of the commitments
    group_elements += commitments;

    // Proof for the opening of the coefficients, commitments to the encryption keys
    group_elements += 2;
    scalar_eleents += 2;

    (group_elements *
      <<C::ToweringCurve as WrappedGroup>::G as GroupEncoding>::Repr::default().as_ref().len()) +
      (scalar_eleents *
        <<C::ToweringCurve as WrappedGroup>::F as PrimeField>::Repr::default().as_ref().len())
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

  /// Prove honest participation in the DKG.
  ///
  /// - Prove `coefficients` coefficients were sampled by evaluations of the eVRF with
  ///   `evrf_private_key`, and committed to correctly.
  /// - Prove shared secrets were correctly derived, and committed to, for each of the
  ///   participants' public keys. The exact randomness used for deriving the shared secret will be
  ///   randomly sampled and should not be expected to be deterministic.
  ///
  /// `transcript` MUST _already_ be binding to `participant_public_keys` and the corresponding
  /// public key for `evrf_public_key`.
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
          // 0 would produce the identity, which isn't representable within the discrete-log proof
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
    debug_assert_eq!(
      vector_commitments.len(),
      Self::vector_commitments(coefficients.len(), participant_public_keys.len())
    );

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

    let (statement, Some(witness)) = (match circuit.statement(
      generators.reduce(generators_to_use).ok_or(AcProveError::IncorrectAmountOfGenerators)?,
      commited_commitments,
    ) {
      Ok(result) => result,
      Err(
        AcStatementError::ConstrainedNonExistentTerm |
        AcStatementError::ConstrainedNonExistentVectorCommitment |
        AcStatementError::ConstrainedNonExistentCommitment,
      ) => {
        panic!("prover generated an invalid circuit for the eVRF DKG")
      }
      // 'too many commitments' is when they threaten 2**32 or so, so this should be unreachable
      Err(AcStatementError::TooManyCommitments) => {
        panic!("prover generated too large of a circuit for the eVRF DKG")
      }
    }) else {
      panic!("proving yet wasn't yielded the witness");
    };
    statement.prove(&mut *rng, &mut transcript, witness)?;

    Self::reveal(rng, generators, &mut transcript, commitments);

    let proof = transcript.complete();
    debug_assert_eq!(
      proof.len(),
      Self::transcript_len(coefficients.len(), participant_public_keys.len())
    );
    Ok(ProveResult { coefficients, encryption_keys, proof })
  }

  /// Verify participation in the DKG.
  ///
  /// - Prove `coefficients` coefficients were sampled by evaluations of the eVRF with
  ///   `evrf_private_key`, and committed to correctly.
  /// - Prove shared secrets were correctly derived, and committed to, for each of the
  ///   participants' public keys. The exact randomness used for deriving the shared secret will be
  ///   randomly sampled and should not be expected to be deterministic.
  ///
  /// `transcript` MUST _already_ be binding to `participant_public_keys` and `evrf_public_key`.
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
        Self::vector_commitments(coefficients, participant_public_keys.len());
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

      let (statement, None) = (match circuit
        .statement(generators.reduce(generators_to_use).ok_or(())?, all_commitments)
      {
        Ok(result) => result,
        Err(
          AcStatementError::ConstrainedNonExistentTerm |
          AcStatementError::ConstrainedNonExistentVectorCommitment |
          AcStatementError::ConstrainedNonExistentCommitment,
        ) => {
          panic!("verifier generated an invalid circuit for the eVRF DKG")
        }
        // 'too many commitments' is when they threaten 2**32 or so, so this should be unreachable
        Err(AcStatementError::TooManyCommitments) => {
          panic!("verifier generated too large of a circuit for the eVRF DKG")
        }
      }) else {
        panic!("verifying yet was yielded a witness");
      };

      statement.verify(rng, verifier, &mut transcript).map_err(|_| ())?;

      (transcript, ecdh_commitments, pedersen_commitments)
    };

    let openings = Self::verify_reveal(rng, verifier, &mut transcript, pedersen_commitments)?;

    if !transcript.complete().is_empty() {
      Err(())?;
    }

    let coefficients = openings[.. coefficients].to_vec();
    let encryption_key_commitments = openings[coefficients.len() ..].to_vec();
    Ok(Verified { coefficients, ecdh_commitments, encryption_key_commitments })
  }
}

#[test]
fn proof() {
  use std::time::Instant;
  use rand_core::OsRng;
  use ciphersuite::group::Group as _;
  use crate::Ed25519;

  const THRESHOLD: u16 = 3;
  const PARTICIPANTS: u16 = 5;

  let generators = crate::Generators::<Ed25519>::new(THRESHOLD, PARTICIPANTS).0;

  let mut context = [0; 32];
  OsRng.fill_bytes(&mut context);

  let embedded_private_key =
    Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));

  #[expect(clippy::as_conversions)]
  let ecdh_public_keys: [_; PARTICIPANTS as usize] = core::array::from_fn(|_| {
    <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::G::random(&mut OsRng)
  });

  let time = Instant::now();
  let res = Proof::<Ed25519>::prove(
    &mut OsRng,
    &generators,
    context,
    THRESHOLD.into(),
    &ecdh_public_keys,
    &embedded_private_key,
  )
  .unwrap();
  std::println!("Proving time: {:?}", time.elapsed());

  let time = Instant::now();
  let mut verifier = Generators::batch_verifier();
  Proof::<Ed25519>::verify(
    &mut OsRng,
    &generators,
    &mut verifier,
    context,
    THRESHOLD.into(),
    &ecdh_public_keys,
    <Ed25519 as Curves>::EmbeddedCurve::generator() * *embedded_private_key,
    &res.proof,
  )
  .unwrap();
  assert!(generators.verify(verifier));
  std::println!("Verifying time: {:?}", time.elapsed());
}
