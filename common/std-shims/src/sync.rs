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

#[cfg(feature = "std")]
pub use std::sync::OnceLock;
#[cfg(not(feature = "std"))]
pub use spin::Once as OnceLock;

#[rustversion::before(1.80)]
mod before_1_80_lazylock {
  use core::ops::Deref;
  use super::{Mutex, OnceLock};

  /// Shim for `std::sync::LazyLock`.
  pub struct LazyLock<T, F = fn() -> T> {
    f: Mutex<Option<F>>,
    once: OnceLock<T>,
  }
  impl<T, F: FnOnce() -> T> LazyLock<T, F> {
    /// Shim for `std::sync::LazyLock::new`.
    pub const fn new(f: F) -> Self {
      Self { f: Mutex::new(Some(f)), once: OnceLock::new() }
    }
    /// Shim for `std::sync::LazyLock::get_or_init`.
    pub fn get(&self) -> &T {
      // Since this initializer will only be called once, the value in the Mutex will be `Some`
      self.once.get_or_init(|| (self.f.lock().take().unwrap())())
    }
  }
  impl<T, F: FnOnce() -> T> Deref for LazyLock<T, F> {
    type Target = T;
    fn deref(&self) -> &T {
      self.get()
    }
  }
}
#[rustversion::before(1.80)]
pub use before_1_80_lazylock::LazyLock;

#[rustversion::since(1.80)]
pub use std::sync::LazyLock;
