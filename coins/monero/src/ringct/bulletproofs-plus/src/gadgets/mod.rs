use transcript::Transcript;
use ciphersuite::{group::ff::Field, Ciphersuite};

use crate::arithmetic_circuit::{VariableReference, Circuit};

mod bit;
pub use bit::*;

pub mod set_membership;

pub mod elliptic_curve;

/// Assert a variable isn't zero.
// One gate, one contraint.
pub fn assert_non_zero_gadget<T: 'static + Transcript, C: Ciphersuite>(
  circuit: &mut Circuit<T, C>,
  var: VariableReference,
) {
  // Any non-zero variable will have a multiplicative inverse
  let inv = circuit.add_secret_input(if circuit.prover() {
    Some(
      Option::from(circuit.unchecked_value(var).invert())
        .expect("prover is asserting zero is non-zero"),
    )
  } else {
    None
  });
  let ((_, _, one), _) = circuit.product(var, inv);
  circuit.equals_constant(one, C::F::ONE);
}

/// Returns a Bit if the value is non-zero.
// One gate and the combined constraints/gates of assert_non_zero_gadget, Bit::new_from_var.
pub fn is_non_zero_gadget<T: 'static + Transcript, C: Ciphersuite>(
  circuit: &mut Circuit<T, C>,
  var: VariableReference,
) -> Bit {
  // Multiply against the inverse, or 1 if there is no inverse due to this being 0
  // This makes the output 0/1 for an honest prover
  let inv = circuit.add_secret_input(if circuit.prover() {
    Option::from(circuit.unchecked_value(var).invert().unwrap_or(C::F::ONE))
  } else {
    None
  });
  let ((_, _, _), out) = circuit.product(var, inv);

  // Ensure this provided inverse wasn't 0
  // If it wasn't 0, `out` will only be 0 if var was 0. If var was non-zero, it'll be non-zero
  assert_non_zero_gadget(circuit, inv);

  // Convert this to a Bit, as the Bit constructor will assert this is 1 or 0
  Bit::new_from_var(circuit, out)
}
