/*
  MIT License

  Copyright (c) 2022-2025 Luke Parker
  Copyright (c) 2025 core-json Developers

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

#[must_use]
pub(super) fn validate_hex(byte: u8) -> bool {
  let bytes = [byte, b'f', b'f', b'f'];

  /*
    "Mom, can we have SIMD?"
    "We have SIMD at home."
    SIMD at home:
  */

  // We don't care for the order of these bytes within our `u32`
  let bytes = u32::from_ne_bytes(bytes);

  const HIGH_BIT: u32 = 1 << 7;
  const HIGH_BITS: u32 = (HIGH_BIT << 24) | (HIGH_BIT << 16) | (HIGH_BIT << 8) | HIGH_BIT;

  #[expect(clippy::as_conversions)]
  const ZERO_CHAR: u32 =
    ((b'0' as u32) << 24) | ((b'0' as u32) << 16) | ((b'0' as u32) << 8) | (b'0' as u32);
  #[expect(clippy::as_conversions)]
  const DISTANCE_AFTER_NINE: u32 = HIGH_BIT - ((b'9' + 1) as u32);
  const DISTANCES_AFTER_NINE: u32 = (DISTANCE_AFTER_NINE << 24) |
    (DISTANCE_AFTER_NINE << 16) |
    (DISTANCE_AFTER_NINE << 8) |
    DISTANCE_AFTER_NINE;

  const FIFTH_BIT: u32 = 1 << 5;
  const FIFTH_BITS: u32 = (FIFTH_BIT << 24) | (FIFTH_BIT << 16) | (FIFTH_BIT << 8) | FIFTH_BIT;

  #[expect(clippy::as_conversions)]
  const A_CHAR: u32 =
    ((b'a' as u32) << 24) | ((b'a' as u32) << 16) | ((b'a' as u32) << 8) | (b'a' as u32);
  #[expect(clippy::as_conversions)]
  const DISTANCE_AFTER_F: u32 = HIGH_BIT - ((b'f' + 1) as u32);
  const DISTANCES_AFTER_F: u32 = (DISTANCE_AFTER_F << 24) |
    (DISTANCE_AFTER_F << 16) |
    (DISTANCE_AFTER_F << 8) |
    DISTANCE_AFTER_F;

  /*
    If these bytes are ASCII, their high bits won't be set, allowing us to use the eighth bits as
    shields for carries/borrows across the lanes we've defined within the `u32`.
  */
  let bytes_with_high_bits = bytes | HIGH_BITS;

  /*
    We subtract our constants from our packed bytes, with their high bits set. If the
    constant (< 128) exceeds the value within the lower seven bits of each byte, it'll cause the
    eigth bit to be carried, leaving it not set. This lets us efficiently check if the packed
    values are greater than the constants.
  */
  let gte_zero = bytes_with_high_bits.wrapping_sub(ZERO_CHAR);
  /*
    `'a' ..= 'f'` have their fifth bits set. `'A' ..= 'F'` do not, where `A + 32 == 'a'`. This OR
    lets us collapse checking the `'A' ..= 'F'` case into the `'a' ..= 'f'` case.
  */
  let gte_a = (bytes_with_high_bits | FIFTH_BITS).wrapping_sub(A_CHAR);

  /*
    We now add our constants to our packed bytes, where our constants are the distance from a
    boundary to the eight bit. If the constant causes the value's eigth bit to be set, then the
    value was greater than or ewqual to the boundary (as else, it'd be insufficient to carry to the
    eighth bit). This lets us efficiently check if the packed values are less than constants.
  */
  let lte_9 = bytes.wrapping_add(DISTANCES_AFTER_NINE);
  let lte_f = (bytes | FIFTH_BITS).wrapping_add(DISTANCES_AFTER_F);

  /*
    The following use XOR as a combiner, as we want the gte bits set and the lte bits unset. The
    XOR operator would allow the gte bits to not be set, while the lte bits are set, yet any value
    which isn't less than the end of the range will be greater than the start of the range. This
    collapses the possible states to just three:
    - gte bit set, lte bit not set (valid)
    - gte bit set, lte bit set (too high)
    - gte bit not set, lte bit not set (too low)
    The XOR operator is sufficient to isolate the valid state.
  */
  let number = gte_zero ^ lte_9;
  let alpha = gte_a ^ lte_f;
  let number_or_alpha = number | alpha;
  // Finally, require these values to have been ASCII to so these values are well-defined
  let ascii = (!bytes) & HIGH_BITS;
  core::hint::black_box(ascii & number_or_alpha) == HIGH_BITS
}

#[test]
fn test_validate_hex() {
  for i in u8::MIN ..= u8::MAX {
    assert_eq!(validate_hex(i), i.is_ascii_hexdigit());
  }
}
