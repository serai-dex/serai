pub use core::sync::atomic;
#[cfg(all(feature = "alloc", not(feature = "std")))]
pub use extern_alloc::sync::{Arc, Weak};
#[cfg(feature = "std")]
pub use std::sync::{Arc, Weak};

mod mutex_shim {
  #[cfg(not(feature = "std"))]
  mod spin_mutex {
    use core::ops::{Deref, DerefMut};

    // We wrap this in an `Option` so we can consider `None` as poisoned
    pub(super) struct Mutex<T>(spin::Mutex<Option<T>>);

    /// An acquired view of a `Mutex`.
    pub struct MutexGuard<'mutex, T> {
      mutex: spin::MutexGuard<'mutex, Option<T>>,
      // This is `Some` for the lifetime of this guard, and is only represented as an `Option` due
      // to needing to move it on `Drop` (which solely gives us a mutable reference to `self`)
      value: Option<T>,
    }

    impl<T> Mutex<T> {
      pub(super) const fn new(value: T) -> Self {
        Self(spin::Mutex::new(Some(value)))
      }

      pub(super) fn lock(&self) -> MutexGuard<'_, T> {
        let mut mutex = self.0.lock();
        // Take from the `Mutex` so future acquisitions will see `None` unless this is restored
        let value = mutex.take();
        // Check the prior acquisition did in fact restore the value
        assert!(value.is_some(), "locking a `spin::Mutex` held by a thread which panicked");
        MutexGuard { mutex, value }
      }
    }

    impl<T> Deref for MutexGuard<'_, T> {
      type Target = T;
      fn deref(&self) -> &T {
        self.value.as_ref().expect("no value yet checked upon lock acquisition")
      }
    }
    impl<T> DerefMut for MutexGuard<'_, T> {
      fn deref_mut(&mut self) -> &mut T {
        self.value.as_mut().expect("no value yet checked upon lock acquisition")
      }
    }

    impl<T> Drop for MutexGuard<'_, T> {
      fn drop(&mut self) {
        // Restore the value
        *self.mutex = self.value.take();
      }
    }
  }
  #[cfg(not(feature = "std"))]
  pub use spin_mutex::*;

  #[cfg(feature = "std")]
  pub use std::sync::{Mutex, MutexGuard};

  /// A shimmed `Mutex` with an API mutual to `spin` and `std`.
  pub struct ShimMutex<T>(Mutex<T>);
  impl<T> ShimMutex<T> {
    /// Construct a new `Mutex`.
    pub const fn new(value: T) -> Self {
      Self(Mutex::new(value))
    }

    /// Acquire a lock on the contents of the `Mutex`.
    ///
    /// This will panic if the `Mutex` was poisoned.
    ///
    /// On no-`std` environments, the implementation presumably defers to that of a spin lock.
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
pub use spin::Lazy as LazyLock;

#[rustversion::since(1.80)]
#[cfg(not(feature = "std"))]
pub use spin::Lazy as LazyLock;
#[rustversion::since(1.80)]
#[cfg(feature = "std")]
pub use std::sync::LazyLock;
