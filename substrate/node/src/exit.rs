//! A future which resolves when an 'exit' signal is received.

#![expect(clippy::module_inception)]

#[cfg(unix)]
mod exit {
  use core::{
    pin::{self, Pin},
    future::Future,
    task::{Context, Poll},
  };
  use std::io;

  use tokio::signal::unix::*;

  pub(crate) struct Exit([io::Result<Signal>; 3]);
  impl Exit {
    pub(crate) fn new() -> Self {
      Self([
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
        signal(SignalKind::quit()),
      ])
    }
  }
  impl Future for Exit {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
      #[expect(clippy::manual_flatten)]
      for signal in &mut self.0 {
        if let Ok(signal) = signal {
          match pin::pin!(signal).poll_recv(context) {
            Poll::Ready(_) => return Poll::Ready(()),
            Poll::Pending => continue,
          }
        }
      }
      Poll::Pending
    }
  }
}

#[cfg(not(unix))]
mod exit {
  use core::{
    pin::{self, Pin},
    future::Future,
    task::{Context, Poll},
  };
  use std::io;

  pub(crate) struct Exit(Pin<Box<dyn Future<Output = io::Result<()>>>>);
  impl Exit {
    pub(crate) fn new() -> Self {
      Self(Box::pin(tokio::signal::ctrl_c()))
    }
  }
  impl Future for Exit {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
      if matches!(pin::pin!(self.0.as_mut()).poll(context), Poll::Ready(Ok(()))) {
        return Poll::Ready(());
      }
      Poll::Pending
    }
  }
}

pub(super) use exit::*;
