use core::marker::PhantomData;

use generic_array::{sequence::GenericSequence as _, ArrayLength, GenericArray};

use generalized_bulletproofs_circuit_abstraction::Variable;
use generalized_bulletproofs_ec_gadgets::{DiscreteLogParameter, Divisor, PointWithDlog};

use crate::Curves;

/// The variables committed to within Pedersen vector commitments.
///
/// For all variables we must commit to during the ZK proof, we place them on the 'tape'. The tape
/// is a linear representation of every single variable committed to by the proof, from which we
/// can read a collection of variables from/push a collection of variables onto. This offers an API
/// similar to reading/writing to a byte stream, despite working with variables in a ZK proof.
pub(super) struct Tape {
  generators: usize,
  current_position: usize,
}
impl Tape {
  // Construct a new tape.
  pub(super) fn new(generators: usize) -> Self {
    Self { generators, current_position: 0 }
  }

  /// Read a Variable from the tape.
  fn read_one_from_tape(&mut self) -> Variable {
    let commitment = self.current_position / self.generators;
    let index = self.current_position % self.generators;
    let res = Variable::CG { commitment, index };
    self.current_position += 1;
    res
  }

  /// Read a fixed-length array of variables from the tape.
  fn read_from_tape<N: ArrayLength>(&mut self) -> GenericArray<Variable, N> {
    GenericArray::<Variable, N>::generate(|_| self.read_one_from_tape())
  }

  /// Read `PointWithDlog`s, which share a discrete logarithm, from the tape.
  pub(super) fn read_points_with_common_dlog<C: Curves>(
    &mut self,
    quantity: usize,
  ) -> impl use<'_, C> + Iterator<Item = PointWithDlog<C::EmbeddedCurveParameters>> {
    /*
      The tape expects the format of:
        - Discrete logarithm
        - Divisor (zero coefficient, x coefficients, y x**i coefficients, y coefficient)
        - Point (x, y)
      Note the `x` coefficients are only from the power of two, and `i >= 1`.
    */
    let dlog =
      self.read_from_tape::<<C::EmbeddedCurveParameters as DiscreteLogParameter>::ScalarBits>();

    struct PointIterator<'tape, C: Curves>(
      &'tape mut Tape,
      GenericArray<Variable, <C::EmbeddedCurveParameters as DiscreteLogParameter>::ScalarBits>,
      PhantomData<C>,
    );
    impl<C: Curves> Iterator for PointIterator<'_, C> {
      type Item = PointWithDlog<C::EmbeddedCurveParameters>;
      fn next(&mut self) -> Option<Self::Item> {
        let divisor = {
          let zero = self.0.read_one_from_tape();
          let x_from_power_of_2 = self.0.read_from_tape();
          let yx = self.0.read_from_tape();
          let y = self.0.read_one_from_tape();
          Divisor { zero, x_from_power_of_2, yx, y }
        };

        let point = (
          // x coordinate
          self.0.read_one_from_tape(),
          // y coordinate
          self.0.read_one_from_tape(),
        );

        Some(PointWithDlog { dlog: self.1.clone(), divisor, point })
      }
    }

    PointIterator(self, dlog, PhantomData::<C>).take(quantity)
  }

  /// The amount of variables the points with a common discrete logarithm will use on the tape.
  pub(super) fn variables_for_points_with_common_dlog<C: Curves>(quantity: usize) -> usize {
    let mut dummy_tape = Tape::new(usize::MAX);
    for _ in dummy_tape.read_points_with_common_dlog::<C>(quantity) {}
    dummy_tape.current_position
  }
}

pub(super) struct PedersenCommitmentTape {
  pedersen_commitments: usize,
}
impl PedersenCommitmentTape {
  pub(super) fn new() -> Self {
    Self { pedersen_commitments: 0 }
  }
  /// Allocate a Pedersen commitment.
  pub(super) fn allocate_pedersen_commitment(&mut self) -> Variable {
    let res = Variable::V(self.pedersen_commitments);
    self.pedersen_commitments += 1;
    res
  }
}
