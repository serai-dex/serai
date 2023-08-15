use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

use transcript::Transcript;
use ciphersuite::{group::ff::Field, Ciphersuite};

use crate::arithmetic_circuit::{VariableReference, Constraint, Circuit};

/// A Bit, verified to be one or zero, usable in binary operations.
#[derive(Clone, Copy, Debug)]
pub struct Bit {
  pub value: Option<Choice>,
  pub variable: VariableReference,
  pub(crate) minus_one: VariableReference,
}

impl Bit {
  /// Create a new bit from an existing variable.
  // This uses one gate and two constraints.
  pub fn new_from_var<T: 'static + Transcript, C: Ciphersuite>(
    circuit: &mut Circuit<T, C>,
    bit: VariableReference,
  ) -> Bit {
    let l = bit;
    let bit = if circuit.prover() { Some(circuit.unchecked_value(l)) } else { None };
    let r = circuit.add_secret_input(bit.map(|bit| bit - C::F::ONE));

    // Verify this is in fact a valid bit
    {
      let ((l_prod, r_prod, o_prod), _) = circuit.product(l, r);

      // Force the output to be 0, meaning at least one of the factors has to be 0
      circuit.equals_constant(o_prod, C::F::ZERO);

      // l + -r = 1
      // At least one must be 0
      // If l is 0, the only solution for r is -1
      // If r is 0, the only solution for l is 1
      // This forces r to be l - 1
      let mut l_minus_one = Constraint::new("l_minus_one");
      l_minus_one.weight(l_prod, C::F::ONE);
      l_minus_one.weight(r_prod, -C::F::ONE);
      l_minus_one.rhs_offset(C::F::ONE);
      circuit.constrain(l_minus_one);
    }

    Bit { value: bit.map(|bit| bit.ct_eq(&C::F::ONE)), variable: l, minus_one: r }
  }

  /// Create a new bit from a choice.
  pub fn new_from_choice<T: 'static + Transcript, C: Ciphersuite>(
    circuit: &mut Circuit<T, C>,
    choice: Option<Choice>,
  ) -> Bit {
    let bit = choice.map(|choice| C::F::from(u64::from(choice.unwrap_u8())));
    let var = circuit.add_secret_input(bit);
    Self::new_from_var(circuit, var)
  }

  /// Select a variable based on the value of this bit.
  // This uses two gates and one constraint.
  pub fn select<T: 'static + Transcript, C: Ciphersuite>(
    &self,
    circuit: &mut Circuit<T, C>,
    if_false: VariableReference,
    if_true: VariableReference,
  ) -> VariableReference {
    let chosen = circuit.add_secret_input(if circuit.prover() {
      Some(C::F::conditional_select(
        &circuit.unchecked_value(if_false),
        &circuit.unchecked_value(if_true),
        self.value.unwrap(),
      ))
    } else {
      None
    });

    // (bit * if_true) + (-bit_minus_one * if_false)
    // If bit is 0, if_false. If bit is 1, if_true

    // This is rewritten to
    // (bit * if_true) + (-1 * bit_minus_one * if_false)
    // (bit * if_true) - (bit_minus_one * if_false)

    // Perform the gates
    let ((_, _, lo), _) = circuit.product(self.variable, if_true);
    let ((_, _, ro), _) = circuit.product(self.minus_one, if_false);

    // lo - ro == chosen
    // lo - ro - chosen == 0
    let mut chosen_constraint = Constraint::new("chosen");
    chosen_constraint.weight(lo, C::F::ONE);
    chosen_constraint.weight(ro, -C::F::ONE);
    circuit.set_variable_constraint(chosen, chosen_constraint);

    chosen
  }

  /// Select a constant based on the value of this bit.
  pub fn select_constant<T: 'static + Transcript, C: Ciphersuite>(
    &self,
    circuit: &mut Circuit<T, C>,
    if_false: C::F,
    if_true: C::F,
  ) -> VariableReference {
    let chosen = Some(())
      .filter(|_| circuit.prover())
      .map(|_| C::F::conditional_select(&if_false, &if_true, self.value.unwrap()));

    let chosen = circuit.add_secret_input(chosen);

    // Constrain chosen = (if_true * bit) + (-if_false * minus_one)
    let mut chosen_constraint = Constraint::new("chosen");
    // These variable_to_product calls are safe since we know we used in the bit in a product at
    // time of construction
    chosen_constraint.weight(circuit.variable_to_product(self.variable).unwrap(), if_true);
    chosen_constraint.weight(circuit.variable_to_product(self.minus_one).unwrap(), -if_false);
    circuit.set_variable_constraint(chosen, chosen_constraint);

    chosen
  }
}
