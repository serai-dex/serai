//! (De)serialization of length prefixes.
//!
//! SCALE defines (de)serialization of containers as having their length prefixed by a
//! ['compact' integer](
//!   https://docs.polkadot.com/polkadot-protocol/parachain-basics/data-encoding/#data-types
//! ). Borsh defines (de)serialization of containers as having their length prefixed by the
//! little-endian encoding of a [`u32`](https://borsh.io). The latter is pleasant for the
//! simplicity when decoding, and for how SCALE's own compact encoding was replaced within the JAM
//! Codec (the one change made), making it an unstable specification to attempt to match.
//!
//! Unfortunately, Borsh's specification has two issues.
//! 1) [`u32`] is frequently a wasteful amount of space for a length prefix.
//! 2) [`u32`] limits the size of a container to [`u32::MAX`] elements, when such containers are
//!    feasible to create with 4 GB of RAM and encounter an error when attempting to serialize.
//!    Serai assumes serialization is infallible if the writer is infallible, causing every single
//!    container to require a [`u32::MAX`] bound on its length.
//!
//! Here, we look to Substrate, which regularly uses a very useful container type:
//! [`sp_core::bounded::BoundedVec`]. By statically defining the container's maximum length, which
//! is frequently small enough enough to fit within just a byte or two, we are able to optimize how
//! many bytes we use for the length prefix _without_ requiring runtime-parsing of a
//! variable-length length prefix.
//!
//! We define a fixed-length length prefix based on the static information for a container's
//! length's bound. Specifically, we determine if the bound would fit in a `u0`, [`u8`], [`u16`],
//! [`u32`], or [`u64`], before using the smallest viable representation to encode the length
//! prefix.
//!
//! This resolves both problems, at the cost of exhibiting [XKCD 927](https://xkcd.com/927).
//! Additionally, this is wholy incompatible with any Borsh schema except if one considers the
//! length as a series of nested `enum`s resolving to have fixed-length array as a value. It also
//! is less friendly for upgrades than SCALE's compact encoding, as increasing the bound for a type
//! may change its serialization for _all_ instances.

use borsh::io::*;

// These methods don't accept `const BOUND: u64` as we need to promote from `u32` into a `u64` at
// call sites, and we can't do that with const generics at this time.

/// Calculate the length to use for a length prefix.
#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
pub(super) const fn len(bound: u64) -> u8 {
  let bits_needed_to_represent_length = u64::BITS - bound.leading_zeros();
  let bytes_needed_to_represent_length = bits_needed_to_represent_length.div_ceil(u8::BITS);
  if bytes_needed_to_represent_length == 0 {
    return 0;
  }
  // Normalize from `{u8, u16, u24, u32, u40, u48, u56, u64}` to `{u8, u16, u32, u64}`
  // This is safe as `bytes_needed_to_represent_length` is bounded `0 .. 8`
  bytes_needed_to_represent_length.next_power_of_two() as u8
}

/// Read a length prefix.
///
/// This will error if the length prefix read exceeds the declared bound.
pub(super) fn read(bound: u64, reader: &mut impl Read) -> Result<u64> {
  let length_prefix_len = usize::from(len(bound));
  let mut length = [0u8; 8];
  reader.read_exact(&mut length[.. length_prefix_len])?;
  let length = u64::from_le_bytes(length);
  if length > bound {
    Err(Error::other("bound exceeded"))?;
  }
  Ok(length)
}

/// Write a length prefix.
pub(super) fn write(bound: u64, writer: &mut impl Write, length: u64) -> Result<()> {
  let length_prefix_len = usize::from(len(bound));
  writer.write_all(&length.to_le_bytes()[0 .. length_prefix_len])
}

#[test]
fn test_len() {
  // Check the case this is an empty container (effectively a unit type)
  assert_eq!(len(0), 0);

  // Check the powers of two work as expected
  assert_eq!(len(1), 1);
  assert_eq!(len(u64::from(u8::MAX)), 1);

  assert_eq!(len(u64::from(u8::MAX) + 1), 2);
  assert_eq!(len(u64::from(u16::MAX)), 2);

  assert_eq!(len(u64::from(u16::MAX) + 1), 4);
  assert_eq!(len(u64::from(u32::MAX)), 4);

  assert_eq!(len(u64::from(u32::MAX) + 1), 8);
  assert_eq!(len(u64::MAX), 8);

  // Check non-powers of two are padded to powers of two
  assert_eq!(len(u64::MAX & ((1 << 24) - 1)), 4);
  assert_eq!(len(u64::MAX & ((1 << 40) - 1)), 8);
  assert_eq!(len(u64::MAX & ((1 << 48) - 1)), 8);
  assert_eq!(len(u64::MAX & ((1 << 56) - 1)), 8);
}

#[test]
fn test_read() {
  // Check basic sanity cases
  assert_eq!(read(0, &mut [].as_slice()).unwrap(), 0);
  assert_eq!(read(u64::from(u8::MAX), &mut [1].as_slice()).unwrap(), 1);
  assert_eq!(read(u64::from(u16::MAX), &mut [1, 0].as_slice()).unwrap(), 1);

  // Check a length equal to the bound is accepted
  assert_eq!(read(1, &mut [1].as_slice()).unwrap(), 1);

  // Check a length exceeding the bound is rejected
  read(1, &mut [2].as_slice()).unwrap_err();

  // Check short lengths are rejected
  read(u64::MAX, &mut [0].as_slice()).unwrap_err();
  read(u64::MAX, &mut [0; 7].as_slice()).unwrap_err();
}

#[test]
#[expect(clippy::cast_possible_truncation)]
fn test_write() {
  use rand_core::{RngCore as _, OsRng};

  macro_rules! test {
    ($int: ty) => {
      let test = |value| {
        let mut encoding = vec![];
        write(u64::from(<$int>::MAX), &mut encoding, u64::from(value)).unwrap();
        assert_eq!(
          read(u64::from(<$int>::MAX), &mut encoding.as_slice()).unwrap(),
          u64::from(value)
        );
      };

      // Test basic cases
      test(0);
      test(1);
      test(<$int>::MAX);

      // Fuzz test length prefixes
      for _ in 0 .. 100 {
        let value = OsRng.next_u64() as $int;
        test(value);
      }
    };
  }
  test!(u8);
  test!(u16);
  test!(u32);
  test!(u64);
}
