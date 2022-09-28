use std::io;

use curve25519_dalek::{
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY},
};

const VARINT_CONTINUATION_MASK: u8 = 0b1000_0000;

pub(crate) fn varint_len(varint: usize) -> usize {
  ((usize::try_from(usize::BITS - varint.leading_zeros()).unwrap().saturating_sub(1)) / 7) + 1
}

pub(crate) fn write_byte<W: io::Write>(byte: &u8, w: &mut W) -> io::Result<()> {
  w.write_all(&[*byte])
}

pub(crate) fn write_varint<W: io::Write>(varint: &u64, w: &mut W) -> io::Result<()> {
  let mut varint = *varint;
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

pub(crate) fn write_scalar<W: io::Write>(scalar: &Scalar, w: &mut W) -> io::Result<()> {
  w.write_all(&scalar.to_bytes())
}

pub(crate) fn write_point<W: io::Write>(point: &EdwardsPoint, w: &mut W) -> io::Result<()> {
  w.write_all(&point.compress().to_bytes())
}

pub(crate) fn write_raw_vec<T, W: io::Write, F: Fn(&T, &mut W) -> io::Result<()>>(
  f: F,
  values: &[T],
  w: &mut W,
) -> io::Result<()> {
  for value in values {
    f(value, w)?;
  }
  Ok(())
}

pub(crate) fn write_vec<T, W: io::Write, F: Fn(&T, &mut W) -> io::Result<()>>(
  f: F,
  values: &[T],
  w: &mut W,
) -> io::Result<()> {
  write_varint(&values.len().try_into().unwrap(), w)?;
  write_raw_vec(f, values, w)
}

pub(crate) fn read_bytes<R: io::Read, const N: usize>(r: &mut R) -> io::Result<[u8; N]> {
  let mut res = [0; N];
  r.read_exact(&mut res)?;
  Ok(res)
}

pub(crate) fn read_byte<R: io::Read>(r: &mut R) -> io::Result<u8> {
  Ok(read_bytes::<_, 1>(r)?[0])
}

pub(crate) fn read_u64<R: io::Read>(r: &mut R) -> io::Result<u64> {
  read_bytes(r).map(u64::from_le_bytes)
}

pub(crate) fn read_u32<R: io::Read>(r: &mut R) -> io::Result<u32> {
  read_bytes(r).map(u32::from_le_bytes)
}

pub(crate) fn read_varint<R: io::Read>(r: &mut R) -> io::Result<u64> {
  let mut bits = 0;
  let mut res = 0;
  while {
    let b = read_byte(r)?;
    if (bits != 0) && (b == 0) {
      Err(io::Error::new(io::ErrorKind::Other, "non-canonical varint"))?;
    }
    if ((bits + 7) > 64) && (b >= (1 << (64 - bits))) {
      Err(io::Error::new(io::ErrorKind::Other, "varint overflow"))?;
    }

    res += u64::from(b & (!VARINT_CONTINUATION_MASK)) << bits;
    bits += 7;
    b & VARINT_CONTINUATION_MASK == VARINT_CONTINUATION_MASK
  } {}
  Ok(res)
}

// All scalar fields supported by monero-serai are checked to be canonical for valid transactions
// While from_bytes_mod_order would be more flexible, it's not currently needed and would be
// inaccurate to include now. While casting a wide net may be preferable, it'd also be inaccurate
// for now. There's also further edge cases as noted by
// https://github.com/monero-project/monero/issues/8438, where some scalars had an archaic
// reduction applied
pub(crate) fn read_scalar<R: io::Read>(r: &mut R) -> io::Result<Scalar> {
  Scalar::from_canonical_bytes(read_bytes(r)?)
    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "unreduced scalar"))
}

pub(crate) fn read_point<R: io::Read>(r: &mut R) -> io::Result<EdwardsPoint> {
  let bytes = read_bytes(r)?;
  CompressedEdwardsY(bytes)
    .decompress()
    // Ban points which are either unreduced or -0
    .filter(|point| point.compress().to_bytes() == bytes)
    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid point"))
}

pub(crate) fn read_torsion_free_point<R: io::Read>(r: &mut R) -> io::Result<EdwardsPoint> {
  read_point(r)
    .ok()
    .filter(|point| point.is_torsion_free())
    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid point"))
}

pub(crate) fn read_raw_vec<R: io::Read, T, F: Fn(&mut R) -> io::Result<T>>(
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

pub(crate) fn read_vec<R: io::Read, T, F: Fn(&mut R) -> io::Result<T>>(
  f: F,
  r: &mut R,
) -> io::Result<Vec<T>> {
  read_raw_vec(f, read_varint(r)?.try_into().unwrap(), r)
}
