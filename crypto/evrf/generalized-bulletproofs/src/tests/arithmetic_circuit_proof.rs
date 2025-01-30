use rand_core::{RngCore, OsRng};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use crate::{
  ScalarVector, PedersenCommitment, PedersenVectorCommitment, Generators,
  transcript::*,
  arithmetic_circuit_proof::{
    Variable, LinComb, ArithmeticCircuitStatement, ArithmeticCircuitWitness,
  },
  tests::generators,
};

#[test]
fn test_zero_arithmetic_circuit() {
  let generators = generators(1);

  let value = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
  let gamma = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
  let commitment = (generators.g() * value) + (generators.h() * gamma);
  let V = vec![commitment];

  let aL = ScalarVector::<<Ristretto as Ciphersuite>::F>(vec![<Ristretto as Ciphersuite>::F::ZERO]);
  let aR = aL.clone();

  let mut transcript = Transcript::new([0; 32]);
  let commitments = transcript.write_commitments(vec![], V);
  let statement = ArithmeticCircuitStatement::<Ristretto>::new(
    generators.reduce(1).unwrap(),
    vec![],
    commitments.clone(),
  )
  .unwrap();
  let witness = ArithmeticCircuitWitness::<Ristretto>::new(
    aL,
    aR,
    vec![],
    vec![PedersenCommitment { value, mask: gamma }],
  )
  .unwrap();

  let proof = {
    statement.clone().prove(&mut OsRng, &mut transcript, witness).unwrap();
    transcript.complete()
  };
  let mut verifier = Generators::batch_verifier();

  let mut transcript = VerifierTranscript::new([0; 32], &proof);
  let verifier_commmitments = transcript.read_commitments(0, 1);
  assert_eq!(commitments, verifier_commmitments.unwrap());
  statement.verify(&mut OsRng, &mut verifier, &mut transcript).unwrap();
  assert!(generators.verify(verifier));
}

#[test]
fn test_vector_commitment_arithmetic_circuit() {
  let generators = generators(2);
  let reduced = generators.reduce(2).unwrap();

  let v1 = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
  let v2 = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
  let gamma = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
  let commitment = (reduced.g_bold(0) * v1) + (reduced.g_bold(1) * v2) + (generators.h() * gamma);
  let V = vec![];
  let C = vec![commitment];

  let zero_vec =
    || ScalarVector::<<Ristretto as Ciphersuite>::F>(vec![<Ristretto as Ciphersuite>::F::ZERO]);

  let aL = zero_vec();
  let aR = zero_vec();

  let mut transcript = Transcript::new([0; 32]);
  let commitments = transcript.write_commitments(C, V);
  let statement = ArithmeticCircuitStatement::<Ristretto>::new(
    reduced,
    vec![LinComb::empty()
      .term(<Ristretto as Ciphersuite>::F::ONE, Variable::CG { commitment: 0, index: 0 })
      .term(<Ristretto as Ciphersuite>::F::from(2u64), Variable::CG { commitment: 0, index: 1 })
      .constant(-(v1 + (v2 + v2)))],
    commitments.clone(),
  )
  .unwrap();
  let witness = ArithmeticCircuitWitness::<Ristretto>::new(
    aL,
    aR,
    vec![PedersenVectorCommitment { g_values: ScalarVector(vec![v1, v2]), mask: gamma }],
    vec![],
  )
  .unwrap();

  let proof = {
    statement.clone().prove(&mut OsRng, &mut transcript, witness).unwrap();
    transcript.complete()
  };
  let mut verifier = Generators::batch_verifier();

  let mut transcript = VerifierTranscript::new([0; 32], &proof);
  let verifier_commmitments = transcript.read_commitments(1, 0);
  assert_eq!(commitments, verifier_commmitments.unwrap());
  statement.verify(&mut OsRng, &mut verifier, &mut transcript).unwrap();
  assert!(generators.verify(verifier));
}

#[test]
fn fuzz_test_arithmetic_circuit() {
  let generators = generators(32);

  for i in 0 .. 100 {
    dbg!(i);

    // Create aL, aR, aO
    let mut aL = ScalarVector(vec![]);
    let mut aR = ScalarVector(vec![]);
    while aL.len() < ((OsRng.next_u64() % 8) + 1).try_into().unwrap() {
      aL.0.push(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
    }
    while aR.len() < aL.len() {
      aR.0.push(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
    }
    let aO = aL.clone() * &aR;

    // Create C
    let mut C = vec![];
    while C.len() < (OsRng.next_u64() % 16).try_into().unwrap() {
      let mut g_values = ScalarVector(vec![]);
      while g_values.0.len() < ((OsRng.next_u64() % 8) + 1).try_into().unwrap() {
        g_values.0.push(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
      }
      C.push(PedersenVectorCommitment {
        g_values,
        mask: <Ristretto as Ciphersuite>::F::random(&mut OsRng),
      });
    }

    // Create V
    let mut V = vec![];
    while V.len() < (OsRng.next_u64() % 4).try_into().unwrap() {
      V.push(PedersenCommitment {
        value: <Ristretto as Ciphersuite>::F::random(&mut OsRng),
        mask: <Ristretto as Ciphersuite>::F::random(&mut OsRng),
      });
    }

    // Generate random constraints
    let mut constraints = vec![];
    for _ in 0 .. (OsRng.next_u64() % 8).try_into().unwrap() {
      let mut eval = <Ristretto as Ciphersuite>::F::ZERO;
      let mut constraint = LinComb::empty();

      for _ in 0 .. (OsRng.next_u64() % 4) {
        let index = usize::try_from(OsRng.next_u64()).unwrap() % aL.len();
        let weight = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
        constraint = constraint.term(weight, Variable::aL(index));
        eval += weight * aL[index];
      }

      for _ in 0 .. (OsRng.next_u64() % 4) {
        let index = usize::try_from(OsRng.next_u64()).unwrap() % aR.len();
        let weight = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
        constraint = constraint.term(weight, Variable::aR(index));
        eval += weight * aR[index];
      }

      for _ in 0 .. (OsRng.next_u64() % 4) {
        let index = usize::try_from(OsRng.next_u64()).unwrap() % aO.len();
        let weight = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
        constraint = constraint.term(weight, Variable::aO(index));
        eval += weight * aO[index];
      }

      for (commitment, C) in C.iter().enumerate() {
        for _ in 0 .. (OsRng.next_u64() % 4) {
          let index = usize::try_from(OsRng.next_u64()).unwrap() % C.g_values.len();
          let weight = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
          constraint = constraint.term(weight, Variable::CG { commitment, index });
          eval += weight * C.g_values[index];
        }
      }

      if !V.is_empty() {
        for _ in 0 .. (OsRng.next_u64() % 4) {
          let index = usize::try_from(OsRng.next_u64()).unwrap() % V.len();
          let weight = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
          constraint = constraint.term(weight, Variable::V(index));
          eval += weight * V[index].value;
        }
      }

      constraint = constraint.constant(-eval);

      constraints.push(constraint);
    }

    let mut transcript = Transcript::new([0; 32]);
    let commitments = transcript.write_commitments(
      C.iter().map(|C| C.commit(generators.g_bold_slice(), generators.h()).unwrap()).collect(),
      V.iter().map(|V| V.commit(generators.g(), generators.h())).collect(),
    );

    let statement = ArithmeticCircuitStatement::<Ristretto>::new(
      generators.reduce(16).unwrap(),
      constraints,
      commitments.clone(),
    )
    .unwrap();

    let witness = ArithmeticCircuitWitness::<Ristretto>::new(aL, aR, C.clone(), V.clone()).unwrap();

    let proof = {
      statement.clone().prove(&mut OsRng, &mut transcript, witness).unwrap();
      transcript.complete()
    };
    let mut verifier = Generators::batch_verifier();

    let mut transcript = VerifierTranscript::new([0; 32], &proof);
    let verifier_commmitments = transcript.read_commitments(C.len(), V.len());
    assert_eq!(commitments, verifier_commmitments.unwrap());
    statement.verify(&mut OsRng, &mut verifier, &mut transcript).unwrap();
    assert!(generators.verify(verifier));
  }
}
