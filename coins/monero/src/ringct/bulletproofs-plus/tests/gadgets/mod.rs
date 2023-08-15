use rand_core::OsRng;

use transcript::{Transcript, RecommendedTranscript};

use multiexp::BatchVerifier;
use ciphersuite::{group::ff::Field, Ciphersuite, Vesta};

use crate::{arithmetic_circuit::Circuit, gadgets::is_non_zero_gadget, tests::generators};

mod elliptic_curve;

#[test]
fn test_is_non_zero_gadget() {
  let generators = generators(16);

  fn gadget(
    circuit: &mut Circuit<RecommendedTranscript, Vesta>,
    value_arg: Option<<Vesta as Ciphersuite>::F>,
  ) {
    let value = circuit.add_secret_input(value_arg);
    circuit.product(value, value);
    let res = is_non_zero_gadget(circuit, value);
    if let Some(value) = value_arg {
      assert_eq!(
        circuit.unchecked_value(res.variable),
        if value == <Vesta as Ciphersuite>::F::ZERO {
          <Vesta as Ciphersuite>::F::ZERO
        } else {
          <Vesta as Ciphersuite>::F::ONE
        }
      );
    }
  }

  let transcript = RecommendedTranscript::new(b"Is Non Zero Gadget Test");

  let test = |x| {
    let mut circuit = Circuit::new(generators.per_proof(), true);
    gadget(&mut circuit, Some(x));
    let (commitments, proof) = circuit.prove(&mut OsRng, &mut transcript.clone());
    assert_eq!(commitments, vec![]);

    let mut circuit = Circuit::new(generators.per_proof(), false);
    gadget(&mut circuit, None);
    let mut verifier = BatchVerifier::new(1);
    circuit.verification_statement().verify(
      &mut OsRng,
      &mut verifier,
      &mut transcript.clone(),
      commitments,
      vec![],
      proof,
    );
    assert!(verifier.verify_vartime());
  };

  test(<Vesta as Ciphersuite>::F::ZERO);
  test(<Vesta as Ciphersuite>::F::ONE);
  test(<Vesta as Ciphersuite>::F::random(&mut OsRng));
}
