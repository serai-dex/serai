use rand_core::{RngCore, OsRng};

use multiexp::BatchVerifier;
use group::ff::Field;
use dalek_ff_group::{Scalar, EdwardsPoint};

use crate::{
  Commitment,
  ringct::bulletproofs_plus::{
    Generators,
    aggregate_range_proof::{AggregateRangeStatement, AggregateRangeWitness},
  },
};

#[test]
fn test_aggregate_range_proof() {
  let mut verifier = BatchVerifier::new(16);
  for m in 1 ..= 16 {
    let generators = Generators::new();

    let mut commitments = vec![];
    for _ in 0 .. m {
      commitments.push(Commitment::new(*Scalar::random(&mut OsRng), OsRng.next_u64()));
    }
    let commitment_points = commitments.iter().map(|com| EdwardsPoint(com.calculate())).collect();
    let statement = AggregateRangeStatement::new(generators, commitment_points).unwrap();
    let witness = AggregateRangeWitness::new(&commitments).unwrap();

    let proof = statement.clone().prove(&mut OsRng, witness).unwrap();
    statement.verify(&mut OsRng, &mut verifier, (), proof);
  }
  assert!(verifier.verify_vartime());
}
