pub use core::sync::*;
pub use alloc::sync::*;

mod mutex_shim {
  #[cfg(feature = "std")]
  pub use std::sync::*;
  #[cfg(not(feature = "std"))]
  pub use spin::*;

  #[derive(Default, Debug)]
  pub struct ShimMutex<T>(Mutex<T>);
  impl<T> ShimMutex<T> {
    pub const fn new(value: T) -> Self {
      Self(Mutex::new(value))
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
      #[cfg(feature = "std")]
      let res = self.0.lock().unwrap();
      #[cfg(not(feature = "std"))]
      let res = self.0.lock();
      res
    }
  }
}
pub use mutex_shim::{ShimMutex as Mutex, MutexGuard};

#[cfg(not(feature = "std"))]
pub use spin::Once as OnceLock;
#[rustversion::before(1.70)]
#[cfg(feature = "std")]
pub use spin::Once as OnceLock;
#[rustversion::since(1.70)]
#[cfg(feature = "std")]
pub use std::sync::OnceLock;

#[cfg(not(feature = "std"))]
pub use spin::Lazy as LazyLock;
#[rustversion::before(1.80)]
#[cfg(feature = "std")]
pub use spin::Lazy as LazyLock;
#[rustversion::since(1.80)]
#[cfg(feature = "std")]
pub use std::sync::LazyLock;
