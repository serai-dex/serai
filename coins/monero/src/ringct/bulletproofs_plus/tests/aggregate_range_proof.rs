use rand_core::{RngCore, OsRng};

use transcript::{Transcript, RecommendedTranscript};

use multiexp::BatchVerifier;
use group::ff::Field;
use dalek_ff_group::Scalar;

use crate::ringct::bulletproofs_plus::{
  RangeCommitment, Generators,
  aggregate_range_proof::{AggregateRangeStatement, AggregateRangeWitness},
};

#[test]
fn test_aggregate_range_proof() {
  let mut verifier = BatchVerifier::new(16);
  for m in 1 ..= 16 {
    let generators = Generators::new();

    let mut commitments = vec![];
    for _ in 0 .. m {
      commitments.push(RangeCommitment::new(OsRng.next_u64(), Scalar::random(&mut OsRng)));
    }
    let commitment_points =
      commitments.iter().map(|com| com.calculate(generators.g(), generators.h())).collect();
    let statement = AggregateRangeStatement::new(generators, commitment_points);
    let witness = AggregateRangeWitness::new(&commitments);

    let mut transcript = RecommendedTranscript::new(b"Aggregate Range Proof Test");
    let proof = statement.clone().prove(&mut OsRng, &mut transcript.clone(), witness);
    statement.verify(&mut OsRng, &mut verifier, &mut transcript, proof);
  }
  assert!(verifier.verify_vartime());
}
