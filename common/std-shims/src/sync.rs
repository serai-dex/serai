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
#[cfg(feature = "std")]
mod std_oncelock {
  #[rustversion::before(1.70)]
  mod before_1_70_oncelock {
    use core::cell::Cell;
    use std::sync::RwLock;

    /// Shim for `std::sync::OnceLock`.
    pub struct OnceLock<T> {
      value: Cell<*mut T>,
      init: RwLock<bool>,
    }
    // We use the `RwLock` (which is `Sync`) to control access to the `!Sync` `RefCell`
    unsafe impl<T: Sync> Sync for OnceLock<T> {}

    impl<T> OnceLock<T> {
      /// Shim for `std::sync::OnceLock::new`.
      pub const fn new() -> Self {
        Self { value: Cell::new(core::ptr::null_mut()), init: RwLock::new(false) }
      }
      /// Shim for `std::sync::OnceLock::get_or_init`.
      pub fn get_or_init<F>(&self, f: F) -> &T
      where
        F: FnOnce() -> T,
      {
        let initialized = *self.init.read().unwrap();
        if !initialized {
          // Obtain an exclusive reference
          let mut initialized = self.init.write().unwrap();
          // If this still isn't initialized (by someone who first obtained an exlusive reference)
          if !*initialized {
            // Set the value and mark it initialized
            self.value.set(Box::into_raw(Box::new(f())));
            *initialized = true;
          }
        }
        // SAFETY: We always initialize the value before this and it's only written to once
        unsafe { &*self.value.get() }
      }
    }

    // SAFETY: `OnceLock` doesn't implement `Clone` so this doesn't risk dropping the `Box`
    // multiple times
    impl<T> Drop for OnceLock<T> {
      fn drop(&mut self) {
        if *self.init.read().unwrap() {
          unsafe { drop(Box::from_raw(self.value.get())) }
        }
      }
    }
  }
  #[rustversion::before(1.70)]
  pub use before_1_70_oncelock::OnceLock;
  #[rustversion::since(1.70)]
  pub use std::sync::OnceLock;
}
#[cfg(feature = "std")]
pub use std_oncelock::OnceLock;

#[cfg(not(feature = "std"))]
pub use spin::Lazy as LazyLock;
#[cfg(feature = "std")]
mod std_lazylock {
  #[rustversion::before(1.80)]
  mod before_1_80_lazylock {
    use core::ops::Deref;
    use crate::sync::{Mutex, OnceLock};

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
      /// Shim for `std::sync::LazyLock::get`.
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
}
#[cfg(feature = "std")]
pub use std_lazylock::LazyLock;
