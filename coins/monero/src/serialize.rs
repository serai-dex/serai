use std::io;

use curve25519_dalek::{scalar::Scalar, edwards::{EdwardsPoint, CompressedEdwardsY}};

pub const VARINT_CONTINUATION_MASK: u8 = 0b1000_0000;

pub fn varint_len(varint: usize) -> usize {
  ((usize::try_from(usize::BITS - varint.leading_zeros()).unwrap().saturating_sub(1)) / 7) + 1
}

pub fn write_varint<W: io::Write>(varint: &u64, w: &mut W) -> io::Result<()> {
  let mut varint = *varint;
  while {
    let mut b = u8::try_from(varint & u64::from(!VARINT_CONTINUATION_MASK)).unwrap();
    varint >>= 7;
    if varint != 0 {
      b |= VARINT_CONTINUATION_MASK;
    }
    w.write_all(&[b])?;
    varint != 0
  } {}
  Ok(())
}

pub fn write_scalar<W: io::Write>(scalar: &Scalar, w: &mut W) -> io::Result<()> {
  w.write_all(&scalar.to_bytes())
}

pub fn write_point<W: io::Write>(point: &EdwardsPoint, w: &mut W) -> io::Result<()> {
  w.write_all(&point.compress().to_bytes())
}

pub fn write_raw_vec<
  T,
  W: io::Write,
  F: Fn(&T, &mut W) -> io::Result<()>
>(f: F, values: &[T], w: &mut W) -> io::Result<()> {
  for value in values {
    f(value, w)?;
  }
  Ok(())
}

pub fn write_vec<
  T,
  W: io::Write,
  F: Fn(&T, &mut W) -> io::Result<()>
>(f: F, values: &[T], w: &mut W) -> io::Result<()> {
  write_varint(&values.len().try_into().unwrap(), w)?;
  write_raw_vec(f, &values, w)
}

pub fn read_byte<R: io::Read>(r: &mut R) -> io::Result<u8> {
  let mut res = [0; 1];
  r.read_exact(&mut res)?;
  Ok(res[0])
}

pub fn read_varint<R: io::Read>(r: &mut R) -> io::Result<u64> {
  let mut bits = 0;
  let mut res = 0;
  while {
    let b = read_byte(r)?;
    res += u64::from(b & (!VARINT_CONTINUATION_MASK)) << bits;
    // TODO: Error if bits exceed u64
    bits += 7;
    b & VARINT_CONTINUATION_MASK == VARINT_CONTINUATION_MASK
  } {}
  Ok(res)
}

pub fn read_32<R: io::Read>(r: &mut R) -> io::Result<[u8; 32]> {
  let mut res = [0; 32];
  r.read_exact(&mut res)?;
  Ok(res)
}

// TODO: Potentially update to Monero's parsing rules on scalars/points, which should be any arbitrary 32-bytes
// We may be able to consider such transactions as malformed and accordingly be opinionated in ignoring them
pub fn read_scalar<R: io::Read>(r: &mut R) -> io::Result<Scalar> {
  Scalar::from_canonical_bytes(
    read_32(r)?
  ).ok_or(io::Error::new(io::ErrorKind::Other, "unreduced scalar"))
}

pub fn read_point<R: io::Read>(r: &mut R) -> io::Result<EdwardsPoint> {
  CompressedEdwardsY(
    read_32(r)?
  ).decompress().filter(|point| point.is_torsion_free()).ok_or(io::Error::new(io::ErrorKind::Other, "invalid point"))
}

pub fn read_raw_vec<R: io::Read, T, F: Fn(&mut R) -> io::Result<T>>(f: F, len: usize, r: &mut R) -> io::Result<Vec<T>> {
  let mut res = Vec::with_capacity(
    len.try_into().map_err(|_| io::Error::new(io::ErrorKind::Other, "length exceeds usize"))?
  );
  for _ in 0 .. len {
    res.push(f(r)?);
  }
  Ok(res)
}

pub fn read_vec<R: io::Read, T, F: Fn(&mut R) -> io::Result<T>>(f: F, r: &mut R) -> io::Result<Vec<T>> {
  read_raw_vec(f, read_varint(r)?.try_into().unwrap(), r)
}
