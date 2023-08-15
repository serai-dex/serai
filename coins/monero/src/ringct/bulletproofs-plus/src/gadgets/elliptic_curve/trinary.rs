use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

use crypto_bigint::CheckedAdd;
use ciphersuite::{
  group::ff::{Field, PrimeFieldBits},
  UInt, Ciphersuite,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Trit {
  NegOne,
  Zero,
  One,
}

// The repr(u8) ensures the memory layout allows this
impl ConstantTimeEq for Trit {
  fn ct_eq(&self, other: &Self) -> Choice {
    (*self as u8).ct_eq(&(*other as u8))
  }
}

impl ConditionallySelectable for Trit {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    let a = *a as u8;
    let b = *b as u8;
    // Use the u8 conditional_select
    let ret = u8::conditional_select(&a, &b, choice);
    // This cast back should be safe since we take in (presumably) valid Trits and selected one
    // This pattern is also used by subtle itself
    unsafe { *((&ret as *const u8) as *const Trit) }
  }
}

/// Convert a series of Trits back to their original Scalar.
///
/// Primarily useful for debugging.
pub fn trits_to_scalar<C: Ciphersuite>(trits: &[Trit]) -> C::F {
  let mut res = C::F::ZERO;
  let mut base = C::F::ONE;
  for trit in trits {
    let mut component = C::F::conditional_select(&C::F::ZERO, &base, trit.ct_eq(&Trit::One));
    component = C::F::conditional_select(&component, &-base, trit.ct_eq(&Trit::NegOne));
    res += component;

    base *= C::F::from(3);
  }
  res
}

/// Convert a scalar to a series of Trits.
pub fn scalar_to_trits<C: Ciphersuite>(scalar: C::F) -> Vec<Trit> {
  let mut uint = C::FI::ZERO;
  {
    const ERR: &str = "uint for this ciphersuite's field couldn't store a number its field could";
    let mut base = C::FI::ONE;
    let bits = scalar.to_le_bits();
    for (i, bit) in bits.iter().enumerate() {
      uint = Option::from(uint.checked_add(&C::FI::conditional_select(
        &C::FI::ZERO,
        &base,
        Choice::from(u8::from(*bit)),
      )))
      .expect(ERR);
      if i != (bits.len() - 1) {
        base = Option::from(base.checked_add(&base)).expect(ERR);
      }
    }
  }

  let mut carry = Choice::from(0);
  let mut res = vec![];
  // TODO: This needs to run a fixed amount of times. Until then, it's still not const time
  while uint != C::FI::ZERO {
    let rem;
    // TODO: Use an optimized division statement. This is using a 256-bit divisor for a 2-bit value
    (uint, rem) = uint.div_rem(C::FI::from(3));

    let new_carry;
    res.push(if rem == C::FI::ZERO {
      // Handle carry
      new_carry = Choice::from(0);
      Trit::conditional_select(&Trit::Zero, &Trit::One, carry)
    } else if rem == C::FI::ONE {
      // Propagate carry
      new_carry = carry;
      Trit::conditional_select(&Trit::One, &Trit::NegOne, carry)
    } else {
      // Set carry
      new_carry = Choice::from(1);
      Trit::conditional_select(&Trit::NegOne, &Trit::Zero, carry)
    });
    carry = new_carry;
  }
  res.push(Trit::conditional_select(&Trit::Zero, &Trit::One, carry));

  debug_assert_eq!(
    scalar,
    trits_to_scalar::<C>(&res),
    "converted a scalar to trits we couldn't convert back"
  );
  res
}
