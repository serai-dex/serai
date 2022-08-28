// Constant time if told to AND this isn't a test with variable time (--all-features)
#[cfg(all(not(all(feature = "variable-time", test)), feature = "constant-time"))]
pub(crate) mod constant_time;

// Variable time if told to AND (this isn't constant time OR this is a test)
#[cfg(all(any(not(feature = "constant-time"), test), feature = "variable-time"))]
pub(crate) mod variable_time;

pub mod scalar {
  #[cfg(all(not(all(feature = "variable-time", test)), feature = "constant-time"))]
  pub use crate::hazmat::backend::constant_time::scalar::*;

  #[cfg(all(any(not(feature = "constant-time"), test), feature = "variable-time"))]
  pub use crate::hazmat::backend::variable_time::scalar::*;
}

pub mod field {
  #[cfg(all(not(all(feature = "variable-time", test)), feature = "constant-time"))]
  pub use crate::hazmat::backend::constant_time::field::*;

  #[cfg(all(any(not(feature = "constant-time"), test), feature = "variable-time"))]
  pub use crate::hazmat::backend::variable_time::field::*;
}
