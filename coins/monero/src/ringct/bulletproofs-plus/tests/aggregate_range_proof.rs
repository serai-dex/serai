use rand_core::{RngCore, OsRng};

use transcript::{Transcript, RecommendedTranscript};

use multiexp::BatchVerifier;
use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto, Pallas, Vesta};

use crate::{
  RANGE_PROOF_BITS, RangeCommitment,
  aggregate_range_proof::{AggregateRangeStatement, AggregateRangeWitness},
  tests::generators,
};

fn test_aggregate_range_proof<C: Ciphersuite>() {
  let mut verifier = BatchVerifier::new(16);
  let generators = generators(RANGE_PROOF_BITS * 16);
  for m in 1 ..= 16 {
    let generators = generators.per_proof();

    let mut commitments = vec![];
    for _ in 0 .. m {
      commitments
        .push(RangeCommitment::new(OsRng.next_u64(), <C as Ciphersuite>::F::random(&mut OsRng)));
    }
    let commitment_points = commitments
      .iter()
      .map(|com| com.calculate(generators.g().point(), generators.h().point()))
      .collect();
    let statement = AggregateRangeStatement::<_, C>::new(generators, commitment_points);
    let witness = AggregateRangeWitness::<C>::new(&commitments);

    let mut transcript = RecommendedTranscript::new(b"Aggregate Range Proof Test");
    let proof = statement.clone().prove(&mut OsRng, &mut transcript.clone(), witness);
    statement.verify(&mut OsRng, &mut verifier, &mut transcript, proof);
  }
  assert!(verifier.verify_vartime());
}

#[test]
fn test_aggregate_range_proof_ristretto() {
  test_aggregate_range_proof::<Ristretto>();
}

#[test]
fn test_aggregate_range_proof_pallas() {
  test_aggregate_range_proof::<Pallas>();
}

#[test]
fn test_aggregate_range_proof_vesta() {
  test_aggregate_range_proof::<Vesta>();
}
