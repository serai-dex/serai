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
  pub struct OnceLock<T>(super::Mutex<()>, Option<T>);
  impl<T> OnceLock<T> {
    pub const fn new() -> OnceLock<T> {
      OnceLock(Mutex::new(), None)
    }

    pub fn get(&self) -> Option<&T> {
      self.1.as_ref()
    }

    pub fn get_mut(&mut self) -> Option<&mut T> {
      self.1.as_mut()
    }

    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
      let lock = self.0.lock();
      if self.1.is_none() {
        self.1 = Some(f());
      }
      drop(lock);

      self.1.as_ref().unwrap()
    }
  }
}
#[cfg(not(feature = "std"))]
pub use oncelock_shim::*;
