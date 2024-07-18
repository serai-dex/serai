// The inner product relation is P = sum(g_bold * a, h_bold * b, g * (a * b))

use rand_core::OsRng;

use curve25519_dalek::Scalar;

use monero_generators::H;

use crate::{
  scalar_vector::ScalarVector,
  point_vector::PointVector,
  original::{
    GENERATORS,
    inner_product::{IpStatement, IpWitness},
  },
  BulletproofsBatchVerifier,
};

#[test]
fn test_zero_inner_product() {
  let statement =
    IpStatement::new_without_P_transcript(ScalarVector(vec![Scalar::ONE; 1]), Scalar::ONE);
  let witness = IpWitness::new(ScalarVector::new(1), ScalarVector::new(1)).unwrap();

  let transcript = Scalar::random(&mut OsRng);
  let proof = statement.clone().prove(transcript, witness).unwrap();

  let mut verifier = BulletproofsBatchVerifier::default();
  verifier.0.g_bold = vec![Scalar::ZERO; 1];
  verifier.0.h_bold = vec![Scalar::ZERO; 1];
  statement.verify(&mut verifier, 1, transcript, Scalar::random(&mut OsRng), proof).unwrap();
  assert!(verifier.verify());
}

#[test]
fn test_inner_product() {
  // P = sum(g_bold * a, h_bold * b, g * u * <a, b>)
  let generators = GENERATORS();
  let mut verifier = BulletproofsBatchVerifier::default();
  verifier.0.g_bold = vec![Scalar::ZERO; 32];
  verifier.0.h_bold = vec![Scalar::ZERO; 32];
  for i in [1, 2, 4, 8, 16, 32] {
    let g = H();
    let mut g_bold = vec![];
    let mut h_bold = vec![];
    for i in 0 .. i {
      g_bold.push(generators.G[i]);
      h_bold.push(generators.H[i]);
    }
    let g_bold = PointVector(g_bold);
    let h_bold = PointVector(h_bold);

    let mut a = ScalarVector::new(i);
    let mut b = ScalarVector::new(i);

    for i in 0 .. i {
      a[i] = Scalar::random(&mut OsRng);
      b[i] = Scalar::random(&mut OsRng);
    }

    let P = g_bold.multiexp(&a) + h_bold.multiexp(&b) + (g * a.clone().inner_product(&b));

    let statement =
      IpStatement::new_without_P_transcript(ScalarVector(vec![Scalar::ONE; i]), Scalar::ONE);
    let witness = IpWitness::new(a, b).unwrap();

    let transcript = Scalar::random(&mut OsRng);
    let proof = statement.clone().prove(transcript, witness).unwrap();

    let weight = Scalar::random(&mut OsRng);
    verifier.0.other.push((weight, P));
    statement.verify(&mut verifier, i, transcript, weight, proof).unwrap();
  }
  assert!(verifier.verify());
}
