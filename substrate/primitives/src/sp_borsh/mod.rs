use borsh::io;

mod length_prefix;
mod bounded_vec;
pub use bounded_vec::*;
mod bitvec;
pub use bitvec::*;

/// Implement [`scale`] `trait`s, with the implementations deferring to [`borsh`].
///
/// This macro assumes [`scale`] (`parity-scale-codec`) is available as `scale`.
///
/// These implementations assume [`borsh::BorshSerialize::serialize`] is only fallible if the
/// writer is fallible.
// Each derivation defines new wrapper IO, which presumably non-trivially increases compile-time
// compared to if we had a single implementation that was referred to. Ideally, this'd be improved.
#[doc(hidden)]
#[macro_export]
macro_rules! borsh_as_scale {
  ($name: ident) => {
    $crate::borsh_as_scale!(,$name);
  };
  ($($const: ident $type: ty)*, $name: ident) => {
    impl<$(const $const: $type, )*> scale::Encode for $name<$($const, )*> {
      /// This will panic if the value's [`borsh::BorshSerialize::serialize`] method errors when
      /// given an infallible `W: Write`.
      //
      // This is sub-optimal in that for value types, we should instead implement `using_encoded`,
      // and we also don't implement [`parity_scale_codec::Encode::size_hint`]. This is the
      // portable solution however.
      fn encode_to<O: ?Sized + scale::Output>(&self, output: &mut O) {
        // Wrap the [`parity_scale_codec::Output`] into a [`borsh::io::Write`] instance.
        struct Writer<'output, O: ?Sized + scale::Output>(&'output mut O);
        impl<O: ?Sized + scale::Output> borsh::io::Write for Writer<'_, O> {
          fn write(&mut self, bytes: &[u8]) -> Result<usize, borsh::io::Error> {
            self.0.write(bytes);
            Ok(bytes.len())
          }
          fn flush(&mut self) -> Result<(), borsh::io::Error> {
            Ok(())
          }
        }

        <Self as borsh::BorshSerialize>::serialize(self, &mut Writer(output)).unwrap();
      }
    }
    impl<
      $(const $const: $type, )*
     > scale::EncodeLike<$name<$($const, )*>> for $name<$($const, )*> {}

    impl<$(const $const: $type, )*> scale::Decode for $name<$($const, )*> {
      fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        // Wrap the [`parity_scale_codec::Input`] into a [`borsh::io::Read`] instance.
        struct Reader<'input, I: scale::Input>(&'input mut I, Option<scale::Error>);
        impl<I: scale::Input> borsh::io::Read for Reader<'_, I> {
          // Implement [`borsh::io::Read::read`] as [`borsh::io::Read::read_exact`], as that's the
          // functionality [`parity_scale_codec::Input`] grants us.
          //
          // While this may be sub-optimal, [`borsh::io::Read::read`] is allowed to block instead
          // of returning the amount of bytes it could immediately read/an error.
          fn read(&mut self, bytes: &mut [u8]) -> Result<usize, borsh::io::Error> {
            /*
              Call [`parity_scale_codec::Input::on_before_alloc_mem`], as required to later
              implement [`parity_scale_codec::DecodeWithMemTracking`].

              We are allowed to be inaccurate with this, and due to not having an exact, bespoke
              implementation present, we assume the size of the encoding is comparable to the
              amount of memory allocated. This is _fine_ even if not _great_.
            */
            if let Err(e) =
              self.0.on_before_alloc_mem(bytes.len()).and_then(|()| self.0.read(bytes))
            {
              self.1 = Some(e);
              return Err(borsh::io::Error::other(""))?;
            }
            Ok(bytes.len())
          }
        }

        let mut reader = Reader(input, None);
        <Self as borsh::BorshDeserialize>::deserialize_reader(&mut reader)
          .map_err(|_| reader.1.expect("Reader::read errored but didn't set the error"))
      }
    }
    impl<$(const $const: $type, )*> scale::DecodeWithMemTracking for $name<$($const, )*> {}
  };
}

/// A wrapper for a reader which enforces a bound on the amount of bytes read.
#[doc(hidden)]
pub struct BoundedReader<'reader, R: io::Read, const BOUND: usize> {
  reader: &'reader mut R,
  read: usize,
}
impl<'reader, R: io::Read, const BOUND: usize> From<&'reader mut R>
  for BoundedReader<'reader, R, BOUND>
{
  fn from(reader: &'reader mut R) -> Self {
    Self { reader, read: 0 }
  }
}
impl<R: io::Read, const BOUND: usize> io::Read for BoundedReader<'_, R, BOUND> {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    let read = self.reader.read(buf)?;
    self.read = self.read.saturating_add(read);
    if self.read > BOUND {
      Err(io::Error::other("read amount of bytes exceeded the bound"))?;
    }
    Ok(read)
  }
}
impl<R: io::Read, const BOUND: usize> BoundedReader<'_, R, BOUND> {
  /// The amount of bytes read via this wrapper.
  #[doc(hidden)]
  pub fn bytes_read(&self) -> usize {
    self.read
  }
}
