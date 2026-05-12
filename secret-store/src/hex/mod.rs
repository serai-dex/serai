mod core_json;

fn decode_hex_char(mut byte: u8) -> Result<u8, ()> {
  // `core_json`'s `validate_hex` is used as it was written in an SIMD-esque fashion, and
  // accordingly has no branches, array indexing, nor usage of non-stack memory
  if !core_json::validate_hex(byte) {
    Err(())?;
  }

  // Convert `64 .. 96` (`b'A' ..= b'F'`) to `96 .. 128` (`b'a' ..= b'f'`)
  byte |= (byte & (1 << 6)) >> 1;

  let alpha = core::hint::black_box((byte >> 6) & 1);
  let numeric = core::hint::black_box(1u8.wrapping_sub(alpha));
  let base = alpha.wrapping_mul(b'a' - 10) | numeric.wrapping_mul(b'0');
  Ok(byte.wrapping_sub(base))
}

/// Constant-time (and secret-respecting) hex decoding.
pub(super) fn decode(bytes: &[u8], dst: &mut [u8]) -> Result<(), ()> {
  if bytes.len() != (2 * dst.len()) {
    Err(())?;
  }

  for (b, byte) in bytes.iter().enumerate() {
    let val = decode_hex_char(*byte)?;
    dst[b / 2] |= val << (4 * (1 - (b % 2)));
  }

  Ok(())
}

/// Constant-time (and secret-respecting) hex encoding.
pub(super) fn encode(bytes: &[u8]) -> String {
  let mut result = String::with_capacity(2 * bytes.len());
  for b in bytes {
    {
      let b = (*b) >> 4;
      let alpha = core::hint::black_box((b.wrapping_add(6)) >> 4);
      result
        .push(char::from(b'0'.wrapping_add(b).wrapping_add(alpha.wrapping_mul(b'a' - b'0' - 10))));
    }
    {
      let b = (*b) & 0b1111;
      let alpha = core::hint::black_box((b.wrapping_add(6)) >> 4);
      result
        .push(char::from(b'0'.wrapping_add(b).wrapping_add(alpha.wrapping_mul(b'a' - b'0' - 10))));
    }
  }
  result
}

#[test]
fn test_decode_hex_char() {
  for b in 0 ..= u8::MAX {
    match b {
      b'0' ..= b'9' => {
        assert_eq!(decode_hex_char(b), Ok(b - b'0'));
      }
      b'A' ..= b'F' => {
        assert_eq!(decode_hex_char(b), Ok(b - b'A' + 10));
      }
      b'a' ..= b'f' => {
        assert_eq!(decode_hex_char(b), Ok(b - b'a' + 10));
      }
      _ => assert_eq!(decode_hex_char(b), Err(())),
    }
  }
}

#[test]
fn test_decode() {
  for b in 0 ..= u8::MAX {
    let mut res = [0];
    decode(format!("{b:02x}").as_bytes(), &mut res).unwrap();
    assert_eq!(res, [b]);
  }
}

#[test]
fn test_encode() {
  for b in 0 ..= u8::MAX {
    assert_eq!(format!("{b:02x}"), encode(&[b]));
  }
}
