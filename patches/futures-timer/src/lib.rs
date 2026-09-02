#![no_std]

extern crate alloc;

use core::{pin::Pin, task::{Poll, Context}, time::Duration};
use alloc::boxed::Box;

#[repr(transparent)]
#[derive(Debug)]
pub struct Delay(Pin<Box<tokio::time::Sleep>>);
impl Delay {
  pub fn new(duration: Duration) -> Self {
    Self(Box::pin(tokio::time::sleep(duration)))
  }

  pub fn reset(&mut self, duration: Duration) {
    *self = Self::new(duration);
  }
}

impl Future for Delay {
  type Output = ();
  fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    self.0.as_mut().poll(context)
  }
}
