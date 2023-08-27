// The inner product relation is P = sum(g_bold * a, h_bold * b, g * (a * y * b), h * alpha)

use rand_core::OsRng;

use multiexp::BatchVerifier;
use group::{ff::Field, Group};
use dalek_ff_group::{Scalar, EdwardsPoint};

use crate::ringct::bulletproofs::plus::{
  ScalarVector, PointVector, GeneratorsList, Generators,
  weighted_inner_product::{WipStatement, WipWitness},
  weighted_inner_product,
};

#[test]
fn test_zero_weighted_inner_product() {
  #[allow(non_snake_case)]
  let P = EdwardsPoint::identity();
  let y = Scalar::random(&mut OsRng);

  let generators = Generators::new().reduce(1);
  let statement = WipStatement::new(generators, P, y);
  let witness = WipWitness::new(ScalarVector::new(1), ScalarVector::new(1), Scalar::ZERO).unwrap();

  let transcript = Scalar::random(&mut OsRng);
  let proof = statement.clone().prove(&mut OsRng, transcript, witness).unwrap();

  let mut verifier = BatchVerifier::new(1);
  statement.verify(&mut OsRng, &mut verifier, (), transcript, proof);
  assert!(verifier.verify_vartime());
}

#[test]
fn test_weighted_inner_product() {
  // P = sum(g_bold * a, h_bold * b, g * (a * y * b), h * alpha)
  let mut verifier = BatchVerifier::new(6);
  let generators = Generators::new();
  for i in [1, 2, 4, 8, 16, 32] {
    let generators = generators.reduce(i);
    let g = generators.g();
    let h = generators.h();
    assert_eq!(generators.len(), i);
    let mut g_bold = vec![];
    let mut h_bold = vec![];
    for i in 0 .. i {
      g_bold.push(generators.generator(GeneratorsList::GBold1, i));
      h_bold.push(generators.generator(GeneratorsList::HBold1, i));
    }
    let g_bold = PointVector(g_bold);
    let h_bold = PointVector(h_bold);

    let mut a = ScalarVector::new(i);
    let mut b = ScalarVector::new(i);
    let alpha = Scalar::random(&mut OsRng);

    let y = Scalar::random(&mut OsRng);
    let mut y_vec = ScalarVector::new(g_bold.len());
    y_vec[0] = y;
    for i in 1 .. y_vec.len() {
      y_vec[i] = y_vec[i - 1] * y;
    }

    for i in 0 .. i {
      a[i] = Scalar::random(&mut OsRng);
      b[i] = Scalar::random(&mut OsRng);
    }

    #[allow(non_snake_case)]
    let P = g_bold.multiexp(&a) +
      h_bold.multiexp(&b) +
      (g * weighted_inner_product(&a, &b, &y_vec)) +
      (h * alpha);

    let statement = WipStatement::new(generators, P, y);
    let witness = WipWitness::new(a, b, alpha).unwrap();

    let transcript = Scalar::random(&mut OsRng);
    let proof = statement.clone().prove(&mut OsRng, transcript, witness).unwrap();
    statement.verify(&mut OsRng, &mut verifier, (), transcript, proof);
  }
  assert!(verifier.verify_vartime());
}
