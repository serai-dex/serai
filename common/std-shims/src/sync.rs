pub use core::sync::atomic;
#[cfg(all(feature = "alloc", not(feature = "std")))]
pub use extern_alloc::sync::{Arc, Weak};

mod mutex_shim {
  #[cfg(not(feature = "std"))]
  pub use spin::{Mutex, MutexGuard};
  #[cfg(feature = "std")]
  pub use std::sync::{Mutex, MutexGuard};

  /// A shimmed `Mutex` with an API mutual to `spin` and `std`.
  #[derive(Default, Debug)]
  pub struct ShimMutex<T>(Mutex<T>);
  impl<T> ShimMutex<T> {
    /// Construct a new `Mutex`.
    pub const fn new(value: T) -> Self {
      Self(Mutex::new(value))
    }

    /// Acquire a lock on the contents of the `Mutex`.
    ///
    /// On no-`std` environments, this may spin until the lock is acquired. On `std` environments,
    /// this may panic if the `Mutex` was poisoned.
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

#[rustversion::before(1.80)]
#[cfg(not(feature = "std"))]
pub use spin::Lazy as LazyLock;
#[rustversion::since(1.80)]
#[cfg(feature = "std")]
pub use std::sync::LazyLock;
