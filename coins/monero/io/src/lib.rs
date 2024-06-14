#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::Debug;
use std_shims::{
  vec,
  vec::Vec,
  io::{self, Read, Write},
};

use curve25519_dalek::{
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY},
};

const VARINT_CONTINUATION_MASK: u8 = 0b1000_0000;

mod sealed {
  /// A trait for a number readable/writable as a VarInt.
  ///
  /// This is sealed to prevent unintended implementations.
  pub trait VarInt: TryInto<u64> + TryFrom<u64> + Copy {
    const BITS: usize;
  }

  impl VarInt for u8 {
    const BITS: usize = 8;
  }
  impl VarInt for u32 {
    const BITS: usize = 32;
  }
  impl VarInt for u64 {
    const BITS: usize = 64;
  }
  impl VarInt for usize {
    const BITS: usize = core::mem::size_of::<usize>() * 8;
  }
}

/// The amount of bytes this number will take when serialized as a VarInt.
///
/// This function will panic if the VarInt exceeds u64::MAX.
pub fn varint_len<V: sealed::VarInt>(varint: V) -> usize {
  let varint_u64: u64 = varint.try_into().map_err(|_| "varint exceeded u64").unwrap();
  ((usize::try_from(u64::BITS - varint_u64.leading_zeros()).unwrap().saturating_sub(1)) / 7) + 1
}

/// Write a byte.
///
/// This is used as a building block within generic functions.
pub fn write_byte<W: Write>(byte: &u8, w: &mut W) -> io::Result<()> {
  w.write_all(&[*byte])
}

/// Write a number, VarInt-encoded,.
///
/// This will panic if the VarInt exceeds u64::MAX.
pub fn write_varint<W: Write, U: sealed::VarInt>(varint: &U, w: &mut W) -> io::Result<()> {
  let mut varint: u64 = (*varint).try_into().map_err(|_| "varint exceeded u64").unwrap();
  while {
    let mut b = u8::try_from(varint & u64::from(!VARINT_CONTINUATION_MASK)).unwrap();
    varint >>= 7;
    if varint != 0 {
      b |= VARINT_CONTINUATION_MASK;
    }
    write_byte(&b, w)?;
    varint != 0
  } {}
  Ok(())
}

/// Write a scalar.
pub fn write_scalar<W: Write>(scalar: &Scalar, w: &mut W) -> io::Result<()> {
  w.write_all(&scalar.to_bytes())
}

/// Write a point.
pub fn write_point<W: Write>(point: &EdwardsPoint, w: &mut W) -> io::Result<()> {
  w.write_all(&point.compress().to_bytes())
}

/// Write a list of elements, without length-prefixing,.
pub fn write_raw_vec<T, W: Write, F: Fn(&T, &mut W) -> io::Result<()>>(
  f: F,
  values: &[T],
  w: &mut W,
) -> io::Result<()> {
  for value in values {
    f(value, w)?;
  }
  Ok(())
}

/// Write a list of elements, with length-prefixing,.
pub fn write_vec<T, W: Write, F: Fn(&T, &mut W) -> io::Result<()>>(
  f: F,
  values: &[T],
  w: &mut W,
) -> io::Result<()> {
  write_varint(&values.len(), w)?;
  write_raw_vec(f, values, w)
}

/// Read a constant amount of bytes.
pub fn read_bytes<R: Read, const N: usize>(r: &mut R) -> io::Result<[u8; N]> {
  let mut res = [0; N];
  r.read_exact(&mut res)?;
  Ok(res)
}

/// Read a single byte.
pub fn read_byte<R: Read>(r: &mut R) -> io::Result<u8> {
  Ok(read_bytes::<_, 1>(r)?[0])
}

/// Read a u16, little-endian encoded,.
pub fn read_u16<R: Read>(r: &mut R) -> io::Result<u16> {
  read_bytes(r).map(u16::from_le_bytes)
}

/// Read a u32, little-endian encoded,.
pub fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
  read_bytes(r).map(u32::from_le_bytes)
}

/// Read a u64, little-endian encoded,.
pub fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
  read_bytes(r).map(u64::from_le_bytes)
}

/// Read a canonically-encoded VarInt.
pub fn read_varint<R: Read, U: sealed::VarInt>(r: &mut R) -> io::Result<U> {
  let mut bits = 0;
  let mut res = 0;
  while {
    let b = read_byte(r)?;
    if (bits != 0) && (b == 0) {
      Err(io::Error::other("non-canonical varint"))?;
    }
    if ((bits + 7) >= U::BITS) && (b >= (1 << (U::BITS - bits))) {
      Err(io::Error::other("varint overflow"))?;
    }

    res += u64::from(b & (!VARINT_CONTINUATION_MASK)) << bits;
    bits += 7;
    b & VARINT_CONTINUATION_MASK == VARINT_CONTINUATION_MASK
  } {}
  res.try_into().map_err(|_| io::Error::other("VarInt does not fit into integer type"))
}

/// Read a canonically-encoded scalar.
///
/// Some scalars within the Monero protocol are not enforced to be canonically encoded. For such
/// scalars, they should be represented as `[u8; 32]` and later converted to scalars as relevant.
pub fn read_scalar<R: Read>(r: &mut R) -> io::Result<Scalar> {
  Option::from(Scalar::from_canonical_bytes(read_bytes(r)?))
    .ok_or_else(|| io::Error::other("unreduced scalar"))
}

/// Decompress a canonically-encoded Ed25519 point.
///
/// Ed25519 is of order `8 * l`. This function ensures each of those `8 * l` points have a singular
/// encoding by checking points aren't encoded with an unreduced field element, and aren't negative
/// when the negative is equivalent (0 == -0).
///
/// Since this decodes an Ed25519 point, it does not check the point is in the prime-order
/// subgroup. Torsioned points do have a canonical encoding, and only aren't canonical when
/// considered in relation to the prime-order subgroup.
pub fn decompress_point(bytes: [u8; 32]) -> Option<EdwardsPoint> {
  CompressedEdwardsY(bytes)
    .decompress()
    // Ban points which are either unreduced or -0
    .filter(|point| point.compress().to_bytes() == bytes)
}

/// Read a canonically-encoded Ed25519 point.
///
/// This internally calls `decompress_point` and has the same definition of canonicity. This
/// function does not check the resulting point is within the prime-order subgroup.
pub fn read_point<R: Read>(r: &mut R) -> io::Result<EdwardsPoint> {
  let bytes = read_bytes(r)?;
  decompress_point(bytes).ok_or_else(|| io::Error::other("invalid point"))
}

/// Read a canonically-encoded Ed25519 point, within the prime-order subgroup.
pub fn read_torsion_free_point<R: Read>(r: &mut R) -> io::Result<EdwardsPoint> {
  read_point(r)
    .ok()
    .filter(EdwardsPoint::is_torsion_free)
    .ok_or_else(|| io::Error::other("invalid point"))
}

/// Read a variable-length list of elements, without length-prefixing.
pub fn read_raw_vec<R: Read, T, F: Fn(&mut R) -> io::Result<T>>(
  f: F,
  len: usize,
  r: &mut R,
) -> io::Result<Vec<T>> {
  let mut res = vec![];
  for _ in 0 .. len {
    res.push(f(r)?);
  }
  Ok(res)
}

/// Read a constant-length list of elements.
pub fn read_array<R: Read, T: Debug, F: Fn(&mut R) -> io::Result<T>, const N: usize>(
  f: F,
  r: &mut R,
) -> io::Result<[T; N]> {
  read_raw_vec(f, N, r).map(|vec| vec.try_into().unwrap())
}

/// Read a length-prefixed variable-length list of elements.
pub fn read_vec<R: Read, T, F: Fn(&mut R) -> io::Result<T>>(f: F, r: &mut R) -> io::Result<Vec<T>> {
  read_raw_vec(f, read_varint(r)?, r)
}
