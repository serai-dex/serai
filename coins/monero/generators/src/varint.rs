use std::io;

const VARINT_CONTINUATION_MASK: u8 = 0b1000_0000;
pub(crate) fn write_varint<W: io::Write>(varint: &u64, w: &mut W) -> io::Result<()> {
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
