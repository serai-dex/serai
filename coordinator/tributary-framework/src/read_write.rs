use alloc::vec::Vec;
use std::io;

/// An item which can be read and written.
pub trait ReadWrite: Sized {
  /// Read an instance of `Self`.
  ///
  /// If the reader yields a reachable serialization of a value, it MUST be readable. In other
  /// words, the following round-trip MUST succeed:
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

mod fixed_write {
  use core::mem::MaybeUninit;
  use std::io;

  pub struct FixedWrite<'buf>(&'buf mut [MaybeUninit<u8>]);
  impl io::Write for FixedWrite<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
      if self.0.is_empty() && (!buf.is_empty()) {
        Err(io::Error::new(
          io::ErrorKind::StorageFull,
          "serialization's length exceeded fixed buffer's size",
        ))?;
      }

      let len_to_copy = self.0.len().min(buf.len());
      let dest = self.0.split_off_mut(.. len_to_copy).unwrap();
      unsafe {
        const {
          assert!(core::mem::align_of::<u8>() == 1, "all `u8` pointers are inherently aligned");
        }
        dest
          .as_mut_ptr()
          .copy_from_nonoverlapping(buf.as_ptr().cast::<MaybeUninit<u8>>(), len_to_copy);
      }
      Ok(len_to_copy)
    }

    fn flush(&mut self) -> io::Result<()> {
      Ok(())
    }
  }
  impl Drop for FixedWrite<'_> {
    fn drop(&mut self) {
      assert!(self.0.is_empty());
    }
  }

  /// Write the value to a fixed-length buffer.
  ///
  /// The value's serialization MUST be exactly this length. The write function MUST only fail if
  /// the writer is fallible.
  #[doc(hidden)]
  pub fn fixed_write<const LEN: usize>(
    write: impl Fn(&mut FixedWrite<'_>) -> std::io::Result<()>,
  ) -> [u8; LEN] {
    let mut serialization = MaybeUninit::<[u8; LEN]>::uninit();
    {
      let mut serialization = FixedWrite(serialization.as_mut());
      write(&mut serialization).unwrap();
    }
    // SAFETY: `FixedWrite` panics on drop if it doesn't write to the entire buffer
    unsafe { serialization.assume_init() }
  }
}
pub use fixed_write::fixed_write;
