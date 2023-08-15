use rand_core::OsRng;

use transcript::{Transcript, RecommendedTranscript};

use multiexp::BatchVerifier;
use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use crate::{
  arithmetic_circuit::{Commitment, Constraint, Circuit},
  tests::generators,
};

#[test]
fn test_arithmetic_circuit() {
  let generators = generators(128);
  let g = generators.g().point();
  let h = generators.h().point();

  // Basic circuit for:
  // Commitments x, y, z, z1
  // x * y = z
  // z + 1 = z1

  fn gadget(
    circuit: &mut Circuit<RecommendedTranscript, Ristretto>,
    x_y_z_z1: Option<(
      Commitment<Ristretto>,
      Commitment<Ristretto>,
      Commitment<Ristretto>,
      Commitment<Ristretto>,
    )>,
  ) {
    let x_var = circuit.add_secret_input(x_y_z_z1.as_ref().map(|xyz| xyz.0.value));
    let x_com = circuit.add_committed_input(x_y_z_z1.as_ref().map(|xyz| xyz.0.clone()));

    let y_var = circuit.add_secret_input(x_y_z_z1.as_ref().map(|xyz| xyz.1.value));
    let y_com = circuit.add_committed_input(x_y_z_z1.as_ref().map(|xyz| xyz.1.clone()));

    let z_com = circuit.add_committed_input(x_y_z_z1.as_ref().map(|xyz| xyz.2.clone()));

    let z1_com = circuit.add_committed_input(x_y_z_z1.as_ref().map(|xyz| xyz.3.clone()));

    let ((product_l, product_r, product_o), _o_var) = circuit.product(x_var, y_var);

    let mut next_constraint = Constraint::new("x_com");
    next_constraint
      .weight(product_l, <Ristretto as Ciphersuite>::F::ONE)
      .weight_commitment(x_com, <Ristretto as Ciphersuite>::F::ONE);
    circuit.constrain(next_constraint);

    let mut next_constraint = Constraint::new("y_com");
    next_constraint
      .weight(product_r, <Ristretto as Ciphersuite>::F::ONE)
      .weight_commitment(y_com, <Ristretto as Ciphersuite>::F::ONE);
    circuit.constrain(next_constraint);

    let mut next_constraint = Constraint::new("z_com");
    next_constraint
      .weight(product_o, <Ristretto as Ciphersuite>::F::ONE)
      .weight_commitment(z_com, <Ristretto as Ciphersuite>::F::ONE);
    circuit.constrain(next_constraint);

    let mut next_constraint = Constraint::new("z1_com");
    next_constraint
      .weight(product_o, <Ristretto as Ciphersuite>::F::ONE)
      .weight_commitment(z1_com, <Ristretto as Ciphersuite>::F::ONE)
      .rhs_offset(-<Ristretto as Ciphersuite>::F::ONE);
    circuit.constrain(next_constraint);
  }

  let x = Commitment::masking(&mut OsRng, <Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let y = Commitment::masking(&mut OsRng, <Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let z = Commitment::masking(&mut OsRng, x.value * y.value);
  let z1 = Commitment::masking(&mut OsRng, z.value + <Ristretto as Ciphersuite>::F::ONE);

  let mut transcript = RecommendedTranscript::new(b"Arithmetic Circuit Test");

  let mut circuit = Circuit::new(generators.per_proof(), true);
  gadget(&mut circuit, Some((x.clone(), y.clone(), z.clone(), z1.clone())));
  let (commitments, proof) = circuit.prove(&mut OsRng, &mut transcript.clone());
  assert_eq!(
    commitments,
    vec![x.calculate(g, h), y.calculate(g, h), z.calculate(g, h), z1.calculate(g, h)]
  );

  let mut circuit = Circuit::new(generators.per_proof(), false);
  gadget(&mut circuit, None);
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
