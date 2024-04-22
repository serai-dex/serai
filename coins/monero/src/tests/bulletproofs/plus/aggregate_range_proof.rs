use rand_core::{RngCore, OsRng};

use multiexp::BatchVerifier;
use group::ff::Field;
use dalek_ff_group::Scalar;

use crate::{
  Commitment,
  ringct::bulletproofs::plus::aggregate_range_proof::{
    AggregateRangeStatement, AggregateRangeWitness,
  },
};

#[test]
fn test_aggregate_range_proof() {
  let mut verifier = BatchVerifier::new(16);
  for m in 1 ..= 16 {
    let mut commitments = vec![];
    for _ in 0 .. m {
      commitments.push(Commitment::new(*Scalar::random(&mut OsRng), OsRng.next_u64()));
    }
    let commitment_points = commitments.iter().map(Commitment::calculate).collect();
    let statement = AggregateRangeStatement::new(commitment_points).unwrap();
    let witness = AggregateRangeWitness::new(commitments).unwrap();

    let proof = statement.clone().prove(&mut OsRng, &witness).unwrap();
    statement.verify(&mut OsRng, &mut verifier, (), proof);
  }
  assert!(verifier.verify_vartime());
}
