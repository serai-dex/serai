use super::*;

impl<C: Curves> Proof<C> {
  /// Reveal the openings for a set of Pedersen commitments.
  ///
  /// This function assumes the commitments have already been transcripted. For proving the
  /// openings, non-interactive aggregation is used so the proof is just a pair of Schnorr
  /// signatures.
  ///
  /// Alternatively, to publishing the openings with a pair of Schnorr signatures, the Pedersen
  /// commitments could be constrained to have `mask = 0` (making them equivalent to the openings)
  /// before a single Schnorr signature would prove `mask = 0`. While this would be more efficient,
  /// we do not muck with the randomness of our commitments here.
  pub(super) fn reveal(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C::ToweringCurve>,
    transcript: &mut ProverTranscript,
    commitments: Vec<PedersenCommitment<C::ToweringCurve>>,
  ) {
    // Push the reveal onto the transcript
    for commitment in &commitments {
      transcript.push_point(&(generators.g() * commitment.value));
    }

    // Prove the openings of the commitments were correct
    let mut weighted_values = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::ZERO);
    let mut weighted_blinding_factors = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::ZERO);
    for commitment in commitments {
      let weight = transcript.challenge::<C::ToweringCurve>();
      *weighted_values += commitment.value * weight;
      *weighted_blinding_factors += commitment.mask * weight;
    }

    // Produce PoKs for the weighted-sum of the Pedersen commitments' values, blinding factors
    let r_values = Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::random(&mut *rng));
    let r_blinding_factors =
      Zeroizing::new(<C::ToweringCurve as WrappedGroup>::F::random(&mut *rng));
    transcript.push_point(&(generators.g() * r_values.deref()));
    transcript.push_point(&(generators.h() * r_blinding_factors.deref()));
    let c = transcript.challenge::<C::ToweringCurve>();
    transcript.push_scalar((c * weighted_values.deref()) + r_values.deref());
    transcript.push_scalar((c * weighted_blinding_factors.deref()) + r_blinding_factors.deref());
  }

  /// Verify the openings for the Pedersen commitments.
  ///
  /// This returns the commitments to the values (sans randomness).
  pub(super) fn verify_reveal(
    rng: &mut (impl RngCore + CryptoRng),
    batch_verifier: &mut BatchVerifier<C::ToweringCurve>,
    transcript: &mut VerifierTranscript,
    pedersen_commitments: Vec<<C::ToweringCurve as WrappedGroup>::G>,
  ) -> Result<Vec<<C::ToweringCurve as WrappedGroup>::G>, ()> {
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
        for (pedersen_commitment, opening) in pedersen_commitments.into_iter().zip(&openings) {
          let weight = transcript.challenge::<C::ToweringCurve>();
          weighted_sum_commitments.push((weight, pedersen_commitment));
          weighted_sum_openings.push((weight, *opening));
        }
        (
          multiexp::multiexp_vartime(&weighted_sum_commitments),
          multiexp::multiexp_vartime(&weighted_sum_openings),
        )
      };
      #[expect(non_snake_case)]
      let A_values = weighted_sum_openings;
      #[expect(non_snake_case)]
      let A_blinding_factors = weighted_sum_commitments - weighted_sum_openings;

      // Verify the proof that the openings were well-defined
      #[expect(non_snake_case)]
      let R_values = transcript.read_point::<C::ToweringCurve>().map_err(|_| ())?;
      #[expect(non_snake_case)]
      let R_blinding_factors = transcript.read_point::<C::ToweringCurve>().map_err(|_| ())?;
      let c = transcript.challenge::<C::ToweringCurve>();

      {
        let s_values = transcript.read_scalar::<C::ToweringCurve>().map_err(|_| ())?;

        let weight = <C::ToweringCurve as WrappedGroup>::F::random(&mut *rng);
        batch_verifier.additional.push((weight, R_values));
        batch_verifier.additional.push((weight * c, A_values));
        batch_verifier.g -= weight * s_values;
      }
      {
        let s_blinding_factors = transcript.read_scalar::<C::ToweringCurve>().map_err(|_| ())?;

        let weight = <C::ToweringCurve as WrappedGroup>::F::random(&mut *rng);
        batch_verifier.additional.push((weight, R_blinding_factors));
        batch_verifier.additional.push((weight * c, A_blinding_factors));
        batch_verifier.h -= weight * s_blinding_factors;
      }
    }

    Ok(openings)
  }
}

#[test]
fn reveal() {
  use rand_core::OsRng;
  use ciphersuite::{group::Group as _, GroupIo};
  use crate::{Generators, Ed25519};

  let generators = Generators::<Ed25519>::new(1, 1).0;

  for i in 0 .. 4 {
    let mut context = [0; 32];
    OsRng.fill_bytes(&mut context);

    let mut commitments = vec![];
    for _ in 0 .. i {
      commitments.push(PedersenCommitment {
        value: <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::F::random(&mut OsRng),
        mask: <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::F::random(&mut OsRng),
      });
    }

    let mut transcript = ProverTranscript::new(context);
    let _ = transcript.write_commitments::<<Ed25519 as Curves>::ToweringCurve>(
      vec![],
      commitments
        .iter()
        .map(|commitment| commitment.commit(generators.g(), generators.h()))
        .collect::<Vec<_>>(),
    );
    Proof::<Ed25519>::reveal(&mut OsRng, &generators, &mut transcript, commitments.clone());
    let transcript = transcript.complete();

    // Check the bytes are as expected
    {
      let mut transcript = transcript.as_slice();
      // Commitments
      for commitment in &commitments {
        assert_eq!(
          <<Ed25519 as Curves>::ToweringCurve as GroupIo>::read_G(&mut transcript).unwrap(),
          commitment.commit(generators.g(), generators.h())
        );
      }
      // Reveals
      for commitment in &commitments {
        assert_eq!(
          <<Ed25519 as Curves>::ToweringCurve as GroupIo>::read_G(&mut transcript).unwrap(),
          generators.g() * commitment.value
        );
      }
      // Nonces
      for _ in 0 .. 2 {
        assert!(bool::from(
          !<<Ed25519 as Curves>::ToweringCurve as GroupIo>::read_G(&mut transcript)
            .unwrap()
            .is_identity()
        ));
      }
      // Responses
      for _ in 0 .. 2 {
        assert!(bool::from(
          !<<Ed25519 as Curves>::ToweringCurve as GroupIo>::read_F(&mut transcript)
            .unwrap()
            .is_zero()
        ));
      }
      assert!(transcript.is_empty());
    }

    // Check the proof verifies as-is
    let challenge_at_end = {
      let mut transcript = VerifierTranscript::new(context, &transcript);
      let commitments = {
        let verifier_commitments =
          transcript.read_commitments::<<Ed25519 as Curves>::ToweringCurve>(0, i).unwrap();
        assert!(verifier_commitments.C().is_empty());
        assert_eq!(
          verifier_commitments.V(),
          &commitments
            .iter()
            .map(|commitment| commitment.commit(generators.g(), generators.h()))
            .collect::<Vec<_>>()
        );
        verifier_commitments.V().to_vec()
      };
      let mut verifier = generalized_bulletproofs::Generators::batch_verifier();
      Proof::<Ed25519>::verify_reveal(&mut OsRng, &mut verifier, &mut transcript, commitments)
        .unwrap();
      assert!(generators.verify(verifier));
      let challenge = transcript.challenge::<<Ed25519 as Curves>::ToweringCurve>();
      assert!(transcript.complete().is_empty());
      challenge
    };

    // Check changing a single byte causes the proof to fail
    let mut one_transcript_made_it_to_end = false;
    for b in 0 .. transcript.len() {
      for x in 1 ..= u8::MAX {
        let mut transcript = transcript.clone();
        transcript[b] ^= x;
        let mut transcript = VerifierTranscript::new(context, &transcript);
        let Ok(commitments) =
          transcript.read_commitments::<<Ed25519 as Curves>::ToweringCurve>(0, i)
        else {
          continue;
        };
        let mut verifier = generalized_bulletproofs::Generators::batch_verifier();
        if Proof::<Ed25519>::verify_reveal(
          &mut OsRng,
          &mut verifier,
          &mut transcript,
          commitments.V().to_vec(),
        )
        .is_ok()
        {
          // If this was syntactically valid, ensure it's semantically invalid
          assert!(!generators.verify(verifier));
        }
        assert_ne!(transcript.challenge::<<Ed25519 as Curves>::ToweringCurve>(), challenge_at_end);
        one_transcript_made_it_to_end |= transcript.complete().is_empty();
        break;
      }
    }
    assert!(one_transcript_made_it_to_end);
  }
}
