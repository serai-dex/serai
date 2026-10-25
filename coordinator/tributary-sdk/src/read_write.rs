use alloc::vec::Vec;
use std::io;

/// An item which can be read and written.
pub trait ReadWrite: Sized {
  /// Read an instance of `Self`.
  ///
  /// If the reader yields a reachable serialization of a transaction, it MUST be readable. In
  /// other, words, the following round-trip MUST succeed:
  ///
  /// ```rs
  /// let serialization = item.serialize();
  /// let mut serialization = serialization.as_slice();
  /// let item2 = I::read(&mut serialization).unwrap();
  /// // Functional equivalence in all regards, not just `<I as PartialEq>::eq` returning `true`
  /// assert_eq!(item, item2);
  /// assert!(serialization.is_empty());
  /// ```
  ///
  /// Additionally, the item MUST be self-delimited and MUST NOT read to the end.
  fn read(reader: impl io::Read) -> io::Result<Self>;

  /// Write the value of `self`.
  ///
  /// This MUST be infallible except if the writer fails.
  fn write(&self, writer: impl io::Write) -> io::Result<()>;

  /// Serialize `self` to a `Vec<u8>`.
  ///
  /// This is infallible as [`ReadWrite::write`] is infallible except if the writer fails, and
  /// `<Vec<u8> as Write>` is infallible.
  fn serialize(&self) -> Vec<u8> {
    let mut result = Vec::with_capacity(96);
    self.write(&mut result).expect("`<Vec<u8> as Write>` is infallible");
    result
  }
}

pub(crate) fn serialized_len(value: &impl ReadWrite) -> io::Result<usize> {
  struct SerializedLength(usize);
  impl io::Write for SerializedLength {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
      if buf.len() > (usize::MAX - self.0) {
        Err(io::Error::new(
          io::ErrorKind::StorageFull,
          "serialization's length exceeded `usize::MAX`",
        ))?;
      }
      self.0 += buf.len();
      Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
      Ok(())
    }
  }

  let mut length = SerializedLength(0);
  let () = value.write(&mut length)?;
  Ok(length.0)
}

#[derive(Clone)]
#[repr(transparent)]
#[doc(hidden)]
pub struct ReadWriteAsBorsh<RW: ReadWrite>(pub RW);
impl<'rw, RW: ReadWrite> From<&'rw RW> for &'rw ReadWriteAsBorsh<RW> {
  fn from(rw: &'rw RW) -> Self {
    // SAFETY: `repr(transparent)`
    unsafe { &*core::ptr::from_ref(rw).cast::<ReadWriteAsBorsh<RW>>() }
  }
}
impl<RW: ReadWrite> borsh::BorshSerialize for ReadWriteAsBorsh<RW> {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> Result<(), io::Error> {
    ReadWrite::write(&self.0, writer)
  }
}
impl<RW: ReadWrite> borsh::BorshDeserialize for ReadWriteAsBorsh<RW> {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> Result<Self, io::Error> {
    ReadWrite::read(reader).map(Self)
  }
}
