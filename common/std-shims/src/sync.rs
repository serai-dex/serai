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
mod oncelock_shim {
  use spin::Once;

  pub struct OnceLock<T>(Once<T>);
  impl<T> OnceLock<T> {
    pub const fn new() -> OnceLock<T> {
      OnceLock(Once::new())
    }
    pub fn get(&self) -> Option<&T> {
      self.0.poll()
    }
    pub fn get_mut(&mut self) -> Option<&mut T> {
      self.0.get_mut()
    }

    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
      self.0.call_once(f)
    }
  }
}
#[cfg(not(feature = "std"))]
pub use oncelock_shim::*;
