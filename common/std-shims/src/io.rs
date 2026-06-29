#[cfg(not(feature = "std"))]
mod shims {
  use core::fmt::{self, Debug, Display, Formatter};
  #[cfg(feature = "alloc")]
  use extern_alloc::{boxed::Box, vec::Vec};
  use crate::error::Error as CoreError;

  /// The kind of error.
  #[derive(Clone, Copy, PartialEq, Eq, Debug)]
  pub enum ErrorKind {
    /// The stream unexpectedly hit EOF.
    UnexpectedEof,
    /// Another kind of error occurred.
    Other,
  }

  /// An error.
  #[derive(Debug)]
  pub struct Error {
    kind: ErrorKind,
    #[cfg(feature = "alloc")]
    error: Box<dyn Send + Sync + CoreError>,
  }

  impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
      <Self as Debug>::fmt(self, f)
    }
  }
  impl CoreError for Error {}

  /// A trait for that which can be converted into `Box<dyn Send + Sync + Error>`.
  #[cfg(not(feature = "alloc"))]
  pub trait IntoBoxSendSyncError {}
  #[cfg(not(feature = "alloc"))]
  impl<I> IntoBoxSendSyncError for I {}
  /// A trait for that which can be converted into `Box<dyn Send + Sync + Error>`.
  #[cfg(feature = "alloc")]
  pub trait IntoBoxSendSyncError: Into<Box<dyn Send + Sync + CoreError>> {}
  #[cfg(feature = "alloc")]
  impl<I: Into<Box<dyn Send + Sync + CoreError>>> IntoBoxSendSyncError for I {}

  impl Error {
    /// Create a new error.
    ///
    /// The error object itself is silently dropped when `alloc` is not enabled.
    pub fn new<E: 'static + IntoBoxSendSyncError>(kind: ErrorKind, error: E) -> Error {
      #[cfg(not(feature = "alloc"))]
      let res = Error { kind };
      #[cfg(feature = "alloc")]
      let res = Error { kind, error: error.into() };
      res
    }

    /// Create a new error with `io::ErrorKind::Other` as its kind.
    ///
    /// The error object itself is silently dropped when `alloc` is not enabled.
    pub fn other<E: 'static + IntoBoxSendSyncError>(error: E) -> Error {
      #[cfg(not(feature = "alloc"))]
      let res = Error { kind: ErrorKind::Other };
      #[cfg(feature = "alloc")]
      let res = Error { kind: ErrorKind::Other, error: error.into() };
      res
    }

    /// The kind of error.
    pub fn kind(&self) -> ErrorKind {
      self.kind
    }

    /// Retrieve the inner error.
    #[cfg(feature = "alloc")]
    pub fn into_inner(self) -> Option<Box<dyn Send + Sync + CoreError>> {
      Some(self.error)
    }
  }

  /// A result with `io::Error`.
  pub type Result<T> = core::result::Result<T, Error>;

  /// A shim for [`std::io::Read`](https://doc.rust-lang.org/1.96.0/std/io/trait.Read.html).
  pub trait Read {
    /// Read into the buffer, returning the amount of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Read the exact amount of bytes in the buffer into the buffer.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
      let read = self.read(buf)?;
      if read != buf.len() {
        Err(Error::new(ErrorKind::UnexpectedEof, "reader ran out of bytes"))?;
      }
      Ok(())
    }
  }

  impl Read for &[u8] {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
      let read = buf.len().min(self.len());
      buf[.. read].copy_from_slice(&self[.. read]);
      *self = &self[read ..];
      Ok(read)
    }
  }

  impl<R: Read> Read for &mut R {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
      R::read(*self, buf)
    }
  }

  /// A shim for [`std::io::BufRead`](https://doc.rust-lang.org/1.96.0/std/io/trait.BufRead.html).
  pub trait BufRead: Read {
    /// Fill the internal buffer, returning a reference to it.
    fn fill_buf(&mut self) -> Result<&[u8]>;
    /// Consume `amt` bytes from the buffer.
    fn consume(&mut self, amt: usize);
  }

  impl BufRead for &[u8] {
    fn fill_buf(&mut self) -> Result<&[u8]> {
      Ok(*self)
    }
    fn consume(&mut self, amt: usize) {
      *self = &self[amt ..];
    }
  }

  /// A shim for [`std::io::Write`](https://doc.rust-lang.org/1.96.0/std/io/trait.Write.html).
  pub trait Write {
    /// Write the buffer, returning the amount of bytes written.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;
    /// Write all of the bytes.
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
      if self.write(buf)? != buf.len() {
        Err(Error::new(ErrorKind::UnexpectedEof, "writer ran out of bytes"))?;
      }
      Ok(())
    }
  }

  impl<W: Write> Write for &mut W {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
      W::write(*self, buf)
    }
  }

  #[cfg(feature = "alloc")]
  impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
      self.extend(buf);
      Ok(buf.len())
    }
  }
}
#[cfg(not(feature = "std"))]
pub use shims::*;

#[cfg(feature = "std")]
pub use std::io::{ErrorKind, Error, Result, Read, BufRead, Write};
