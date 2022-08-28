use lazy_static::lazy_static;

use zeroize::Zeroize;

use num_bigint::BigUint;

use crate::field;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct FieldElement(pub(crate) GenericArray<u8, U57>);

// 2**448 - 2**224 - 1
#[rustfmt::skip]
lazy_static! {
  pub static ref MODULUS: FieldElement = FieldElement(
    hex_literal::hex!(
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00"
    ).into()
  );

  static ref MODULUS_INT: BigUint = from_repr_inner(MODULUS.0).unwrap();
}
field!(FieldElement, MODULUS, MODULUS_INT);

lazy_static! {
  pub(crate) static ref Q_4: FieldElement =
    FieldElement(to_repr_inner((&*MODULUS_INT + &BigUint::one()) / BigUint::from(4u8)));
}
