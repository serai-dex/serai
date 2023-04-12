use std::io;

mod merkle;
pub(crate) use merkle::*;

mod transaction;
pub use transaction::*;

mod provided;
pub use provided::*;

mod block;
pub use block::*;

mod blockchain;
pub use blockchain::*;

mod mempool;
pub use mempool::*;

#[cfg(any(test, feature = "tests"))]
pub mod tests;

/// An item which can be read and written.
pub trait ReadWrite: Sized {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self>;
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;

  fn serialize(&self) -> Vec<u8> {
    // BlockHeader is 64 bytes and likely the smallest item in this system
    let mut buf = Vec::with_capacity(64);
    self.write(&mut buf).unwrap();
    buf
  }
}
