#[cfg(feature = "std")]
pub use std::io::*;

#[cfg(not(feature = "std"))]
mod shims {
  use core::fmt::{Debug, Formatter};
  use alloc::{boxed::Box, vec::Vec};

  #[derive(Clone, Copy, PartialEq, Eq, Debug)]
  pub enum ErrorKind {
    UnexpectedEof,
    Other,
  }

  pub struct Error {
    kind: ErrorKind,
    error: Box<dyn Send + Sync>,
  }

  impl Debug for Error {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
      fmt.debug_struct("Error").field("kind", &self.kind).finish_non_exhaustive()
    }
  }

  impl Error {
    pub fn new<E: 'static + Send + Sync>(kind: ErrorKind, error: E) -> Error {
      Error { kind, error: Box::new(error) }
    }

    pub fn other<E: 'static + Send + Sync>(error: E) -> Error {
      Error { kind: ErrorKind::Other, error: Box::new(error) }
    }

    pub fn kind(&self) -> ErrorKind {
      self.kind
    }

    pub fn into_inner(self) -> Option<Box<dyn Send + Sync>> {
      Some(self.error)
    }
  }

  pub type Result<T> = core::result::Result<T, Error>;

  pub trait Read {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

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

  pub trait Write {
    fn write(&mut self, buf: &[u8]) -> Result<usize>;
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
      if self.write(buf)? != buf.len() {
        Err(Error::new(ErrorKind::UnexpectedEof, "writer ran out of bytes"))?;
      }
      Ok(())
    }
  }

  impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
      self.extend(buf);
      Ok(buf.len())
    }
  }
}

#[cfg(not(feature = "std"))]
pub use shims::*;
