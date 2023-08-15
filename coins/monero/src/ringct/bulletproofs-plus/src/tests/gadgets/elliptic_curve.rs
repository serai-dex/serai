use rand_core::OsRng;

use transcript::{Transcript, RecommendedTranscript};

use pasta_curves::arithmetic::CurveAffine;
use multiexp::BatchVerifier;
use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    Group, Curve,
  },
  Ciphersuite, Pallas, Vesta,
};

use crate::{
  arithmetic_circuit::Circuit,
  gadgets::elliptic_curve::{
    Trit, DLogTable, EmbeddedCurveOperations, scalar_to_trits, trits_to_scalar,
  },
  tests::generators as generators_fn,
};

#[test]
fn test_incomplete_addition() {
  let generators = generators_fn(64 * 256);

  let p1 = <Pallas as Ciphersuite>::G::random(&mut OsRng);
  let p2 = <Pallas as Ciphersuite>::G::random(&mut OsRng);
  let p3 = p1 + p2;

  let p1 = p1.to_affine().coordinates().unwrap();
  let p1 = (*p1.x(), *p1.y());

  let p2_orig = p2;
  let p2 = p2.to_affine().coordinates().unwrap();
  let p2 = (*p2.x(), *p2.y());

  let p3 = p3.to_affine().coordinates().unwrap();
  let p3 = (*p3.x(), *p3.y());

  let mut transcript = RecommendedTranscript::new(b"Point Addition Circuit Test");

  let gadget = |circuit: &mut Circuit<RecommendedTranscript, Vesta>| {
    let prover = circuit.prover();

    let p1_x = circuit.add_secret_input(Some(p1.0).filter(|_| prover));
    let p1_y = circuit.add_secret_input(Some(p1.1).filter(|_| prover));

    let p2_x = circuit.add_secret_input(Some(p2.0).filter(|_| prover));
    let p2_y = circuit.add_secret_input(Some(p2.1).filter(|_| prover));

    let p1 = <Vesta as EmbeddedCurveOperations>::constrain_on_curve(circuit, p1_x, p1_y);
    let p2 = <Vesta as EmbeddedCurveOperations>::constrain_on_curve(circuit, p2_x, p2_y);

    let res = <Vesta as EmbeddedCurveOperations>::incomplete_add(circuit, p1, p2);
    circuit.equals_constant(circuit.variable_to_product(res.x()).unwrap(), p3.0);
    circuit.equals_constant(circuit.variable_to_product(res.y()).unwrap(), p3.1);

    let res = <Vesta as EmbeddedCurveOperations>::incomplete_add_constant(circuit, p1, p2_orig);
    circuit.equals_constant(circuit.variable_to_product(res.x()).unwrap(), p3.0);
    circuit.equals_constant(circuit.variable_to_product(res.y()).unwrap(), p3.1);
  };

  let mut circuit = Circuit::new(generators.per_proof(), true);
  gadget(&mut circuit);
  let (commitments, proof) = circuit.prove(&mut OsRng, &mut transcript.clone());
  assert_eq!(commitments, vec![]);

  let mut circuit = Circuit::new(generators.per_proof(), false);
  gadget(&mut circuit);
  let mut verifier = BatchVerifier::new(1);
  circuit.verification_statement().verify(
    &mut OsRng,
    &mut verifier,
    &mut transcript,
    commitments,
    vec![],
    proof,
  );
  assert!(verifier.verify_vartime());
}

#[test]
fn test_trinary() {
  let mut scalar = <Pallas as Ciphersuite>::F::ZERO;
  for _ in 0 ..= 13 {
    assert_eq!(trits_to_scalar::<Pallas>(&scalar_to_trits::<Pallas>(scalar)), scalar);
    scalar += <Pallas as Ciphersuite>::F::ONE;
  }
  assert_eq!(scalar, <Pallas as Ciphersuite>::F::from(14));

  for _ in 0 .. 100 {
    let scalar = <Pallas as Ciphersuite>::F::random(&mut OsRng);
    assert_eq!(trits_to_scalar::<Pallas>(&scalar_to_trits::<Pallas>(scalar)), scalar);
  }

  assert_eq!(
    trits_to_scalar::<Pallas>(&scalar_to_trits::<Pallas>(-<Pallas as Ciphersuite>::F::ONE)),
    -<Pallas as Ciphersuite>::F::ONE
  );
}

#[test]
fn test_dlog_pok() {
  let generators = generators_fn(64 * 256);

  let transcript = RecommendedTranscript::new(b"Point DLog PoK Circuit Test");

  let G_table =
    Box::leak(Box::new(DLogTable::<Pallas>::new(<Pallas as Ciphersuite>::G::generator())));

  let gadget = |circuit: &mut Circuit<RecommendedTranscript, Vesta>, point: (_, _), dlog| {
    let prover = circuit.prover();

    let point_x = circuit.add_secret_input(Some(point.0).filter(|_| prover));
    let point_y = circuit.add_secret_input(Some(point.1).filter(|_| prover));

    let point = <Vesta as EmbeddedCurveOperations>::constrain_on_curve(circuit, point_x, point_y);

    <Vesta as EmbeddedCurveOperations>::dlog_pok(&mut OsRng, circuit, G_table, point, dlog);
  };

  let test = |point: (_, _), dlog| {
    let mut circuit = Circuit::new(generators.per_proof(), true);
    gadget(&mut circuit, point, Some(dlog));
    let (commitments, _, vector_commitments, proof, proofs) =
      circuit.prove_with_vector_commitments(&mut OsRng, &mut transcript.clone());
    assert!(commitments.is_empty());

    let mut circuit = Circuit::new(generators.per_proof(), false);
    gadget(&mut circuit, point, None);

    let mut verifier = BatchVerifier::new(5);
    circuit.verification_statement_with_vector_commitments().verify(
      &mut OsRng,
      &mut verifier,
      &mut transcript.clone(),
      commitments,
      vector_commitments,
      vec![],
      proof,
      proofs,
    );
    assert!(verifier.verify_vartime());
  };

  assert_eq!(<Pallas as Ciphersuite>::F::CAPACITY, <Vesta as Ciphersuite>::F::CAPACITY);

  {
    let point = <Pallas as Ciphersuite>::G::generator().to_affine().coordinates().unwrap();
    let point = (*point.x(), *point.y());
    test(point, <Pallas as Ciphersuite>::F::ONE);
  }

  for _ in 0 .. 8 {
    let dlog = loop {
      let dlog = <Pallas as Ciphersuite>::F::random(&mut OsRng);
      // TODO: Remove once the ecip lib supports odd amounts of points
      if (scalar_to_trits::<Pallas>(dlog).iter().filter(|i| **i != Trit::Zero).count() % 2) != 1 {
        continue;
      }
      break dlog;
    };

    let point = (<Pallas as Ciphersuite>::G::generator() * dlog).to_affine().coordinates().unwrap();
    let point = (*point.x(), *point.y());

    test(point, dlog);
  }

  // TODO: Test every bit being set
}
