use subtle::Choice;

pub(crate) use dalek_ff_group::{constant_time, math_op, math, from_wrapper, from_uint};

pub mod scalar;
pub mod field;
pub mod group;

// Convert a boolean to a Choice in a *presumably* constant time manner
pub(crate) fn choice(value: bool) -> Choice {
  let bit = value as u8;
  debug_assert_eq!(bit | 1, 1);
  Choice::from(bit)
}
