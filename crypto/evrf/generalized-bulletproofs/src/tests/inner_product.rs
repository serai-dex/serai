// The inner product relation is P = sum(g_bold * a, h_bold * b, g * (a * b))

use rand_core::OsRng;

use ciphersuite::{
  group::{ff::Field, Group},
  Ciphersuite, Ristretto,
};

use crate::{
  ScalarVector, PointVector,
  transcript::*,
  inner_product::{P, IpStatement, IpWitness},
  tests::generators,
};

#[test]
fn test_zero_inner_product() {
  let P = <Ristretto as Ciphersuite>::G::identity();

  let generators = generators::<Ristretto>(1);
  let reduced = generators.reduce(1).unwrap();
  let witness = IpWitness::<Ristretto>::new(
    ScalarVector::<<Ristretto as Ciphersuite>::F>::new(1),
    ScalarVector::<<Ristretto as Ciphersuite>::F>::new(1),
  )
  .unwrap();

  let proof = {
    let mut transcript = Transcript::new([0; 32]);
    IpStatement::<Ristretto>::new(
      reduced,
      ScalarVector(vec![<Ristretto as Ciphersuite>::F::ONE; 1]),
      <Ristretto as Ciphersuite>::F::ONE,
      P::Prover(P),
    )
    .unwrap()
    .clone()
    .prove(&mut transcript, witness)
    .unwrap();
    transcript.complete()
  };

  let mut verifier = generators.batch_verifier();
  IpStatement::<Ristretto>::new(
    reduced,
    ScalarVector(vec![<Ristretto as Ciphersuite>::F::ONE; 1]),
    <Ristretto as Ciphersuite>::F::ONE,
    P::Verifier { verifier_weight: <Ristretto as Ciphersuite>::F::ONE },
  )
  .unwrap()
  .verify(&mut verifier, &mut VerifierTranscript::new([0; 32], &proof))
  .unwrap();
  assert!(generators.verify(verifier));
}

#[test]
fn test_inner_product() {
  // P = sum(g_bold * a, h_bold * b)
  let generators = generators::<Ristretto>(32);
  let mut verifier = generators.batch_verifier();
  for i in [1, 2, 4, 8, 16, 32] {
    let generators = generators.reduce(i).unwrap();
    let g = generators.g();
    assert_eq!(generators.len(), i);
    let mut g_bold = vec![];
    let mut h_bold = vec![];
    for i in 0 .. i {
      g_bold.push(generators.g_bold(i));
      h_bold.push(generators.h_bold(i));
    }
    let g_bold = PointVector::<Ristretto>(g_bold);
    let h_bold = PointVector::<Ristretto>(h_bold);

    let mut a = ScalarVector::<<Ristretto as Ciphersuite>::F>::new(i);
    let mut b = ScalarVector::<<Ristretto as Ciphersuite>::F>::new(i);

    for i in 0 .. i {
      a[i] = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
      b[i] = <Ristretto as Ciphersuite>::F::random(&mut OsRng);
    }

    let P = g_bold.multiexp(&a) + h_bold.multiexp(&b) + (g * a.inner_product(b.0.iter()));

    let witness = IpWitness::<Ristretto>::new(a, b).unwrap();

    let proof = {
      let mut transcript = Transcript::new([0; 32]);
      IpStatement::<Ristretto>::new(
        generators,
        ScalarVector(vec![<Ristretto as Ciphersuite>::F::ONE; i]),
        <Ristretto as Ciphersuite>::F::ONE,
        P::Prover(P),
      )
      .unwrap()
      .prove(&mut transcript, witness)
      .unwrap();
      transcript.complete()
    };

    verifier.additional.push((<Ristretto as Ciphersuite>::F::ONE, P));
    IpStatement::<Ristretto>::new(
      generators,
      ScalarVector(vec![<Ristretto as Ciphersuite>::F::ONE; i]),
      <Ristretto as Ciphersuite>::F::ONE,
      P::Verifier { verifier_weight: <Ristretto as Ciphersuite>::F::ONE },
    )
    .unwrap()
    .verify(&mut verifier, &mut VerifierTranscript::new([0; 32], &proof))
    .unwrap();
  }
  assert!(generators.verify(verifier));
}
