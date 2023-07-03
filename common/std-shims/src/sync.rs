pub use core::sync::*;

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
  use super::Mutex;

  pub struct OnceLock<T>(Mutex<bool>, Option<T>);
  impl<T> OnceLock<T> {
    pub const fn new() -> OnceLock<T> {
      OnceLock(Mutex::new(false), None)
    }

    // These return a distinct Option in case of None so another caller using get_or_init doesn't
    // transform it from None to Some
    pub fn get(&self) -> Option<&T> {
      if !*self.0.lock() {
        None
      } else {
        self.1.as_ref()
      }
    }
    pub fn get_mut(&mut self) -> Option<&mut T> {
      if !*self.0.lock() {
        None
      } else {
        self.1.as_mut()
      }
    }

    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
      let mut lock = self.0.lock();
      if !*lock {
        unsafe {
          (core::ptr::addr_of!(self.1) as *mut Option<_>).write_unaligned(Some(f()));
        }
      }
      *lock = true;
      drop(lock);

      self.get().unwrap()
    }
  }
}
#[cfg(not(feature = "std"))]
pub use oncelock_shim::*;
