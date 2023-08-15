use rand_core::{RngCore, OsRng};

use transcript::{Transcript, RecommendedTranscript};

use multiexp::BatchVerifier;
use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use crate::{
  RANGE_PROOF_BITS, RangeCommitment,
  single_range_proof::{SingleRangeStatement, SingleRangeWitness},
  tests::generators,
};

#[test]
fn test_single_range_proof() {
  let generators = generators(RANGE_PROOF_BITS);
  let usable = generators.per_proof();

  let commitment =
    RangeCommitment::new(OsRng.next_u64(), <Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let commitment_point = commitment.calculate(generators.g().point(), generators.h().point());
  let statement = SingleRangeStatement::<_, Ristretto>::new(usable, commitment_point);
  let witness = SingleRangeWitness::<Ristretto>::new(commitment);

  let mut transcript = RecommendedTranscript::new(b"Single Range Proof Test");
  let proof = statement.clone().prove(&mut OsRng, &mut transcript.clone(), witness);
  let mut verifier = BatchVerifier::new(1);
  statement.verify(&mut OsRng, &mut verifier, &mut transcript, proof);
  assert!(verifier.verify_vartime());
}
