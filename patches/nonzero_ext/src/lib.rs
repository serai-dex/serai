#![no_std]

#[macro_export]
macro_rules! nonzero {
  ($n: literal) => {
    const {
      core::num::NonZero::new($n).unwrap()
    }
  }
}
