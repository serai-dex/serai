use lazy_static::lazy_static;

use zeroize::Zeroize;

use num_bigint::BigUint;

use crate::field;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct Scalar(pub(crate) GenericArray::<u8, U57>);

// 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
lazy_static! {
  pub static ref MODULUS: Scalar = Scalar(
    hex_literal::hex!(
      "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00"
    ).into()
  );

  static ref MODULUS_INT: BigUint = from_repr_inner(MODULUS.0).unwrap();
}

field!(Scalar, MODULUS, MODULUS_INT);

impl Scalar {
  pub fn wide_reduce(x: [u8; 114]) -> Scalar {
    Scalar(to_repr_inner(&BigUint::from_bytes_le(x.as_ref()) % &*MODULUS_INT))
  }
}
