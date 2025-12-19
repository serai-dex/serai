use core::cmp::Ord;
use alloc::vec::Vec;

use scale::FullCodec;

/// A trait to obtain an encoding whose lexicographic order corresponds to the value's.
pub trait LexicographicEncoding: Ord + FullCodec {
  /// The representation of the encoding.
  ///
  /// This SHOULD be `[u8; N]` or similar.
  type Encoding: AsMut<[u8]> + Ord + FullCodec;
  /// Encode such that `cmp(e(A), e(B)) == cmp(A, B)`.
  fn lexicographic_encode(&self) -> Self::Encoding;
  /// Decode such that `d(e(A)) == A`.
  fn lexicographic_decode(encoding: Self::Encoding) -> Self;
}

macro_rules! impl_prim_uint {
  ($type: ident) => {
    impl LexicographicEncoding for $type {
      type Encoding = [u8; core::mem::size_of::<Self>()];
      fn lexicographic_encode(&self) -> Self::Encoding {
        self.to_be_bytes()
      }
      fn lexicographic_decode(encoding: Self::Encoding) -> Self {
        Self::from_be_bytes(encoding)
      }
    }
  };
}
impl_prim_uint!(u8);
impl_prim_uint!(u16);
impl_prim_uint!(u32);
impl_prim_uint!(u64);
impl_prim_uint!(u128);

/// A wrapper such that
/// `a.cmp(&b).reverse() == e(LexicographicReverse(a)).cmp(&e(LexicographicReverse(b)))`.
///
/// This allows systems which only allow iterating forwards to iterate backwards by inverting the
/// direction of values via this derivative encoding.
pub struct LexicographicReverse<V: LexicographicEncoding>(V::Encoding);

impl<V: LexicographicEncoding> scale::Decode for LexicographicReverse<V> {
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    V::Encoding::decode(input).map(Self)
  }
}

impl<V: LexicographicEncoding> scale::Encode for LexicographicReverse<V> {
  fn size_hint(&self) -> usize {
    self.0.size_hint()
  }
  fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
    self.0.encode_to(dest);
  }
  fn encode(&self) -> Vec<u8> {
    self.0.encode()
  }
  fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
    self.0.using_encoded(f)
  }
  fn encoded_size(&self) -> usize {
    self.0.encoded_size()
  }
}

impl<V: LexicographicEncoding> scale::EncodeLike for LexicographicReverse<V> {}

/// This is a bijective mapping such that `reverse(reverse(encoding)) == encoding`.
fn reverse<E: AsMut<[u8]>>(mut encoding: E) -> E {
  for byte in encoding.as_mut().iter_mut() {
    *byte = !*byte;
  }
  encoding
}

impl<V: LexicographicEncoding> LexicographicReverse<V> {
  pub(super) fn from_encoding(encoding: V::Encoding) -> Self {
    Self(reverse(encoding))
  }
  pub(super) fn from(value: &V) -> Self {
    Self::from_encoding(value.lexicographic_encode())
  }
  pub(super) fn into(self) -> V {
    V::lexicographic_decode(reverse(self.0))
  }
}

#[test]
fn lexicographic_uint() {
  use rand_core::{RngCore as _, OsRng};

  // Basic sanity checks
  {
    assert_eq!(0u64.lexicographic_encode(), 0u64.lexicographic_encode());
    assert!(0u64.lexicographic_encode() < 1u64.lexicographic_encode());
    assert!(0u64.lexicographic_encode() <= 1u64.lexicographic_encode());
    assert!(1u64.lexicographic_encode() > 0u64.lexicographic_encode());
    assert!(1u64.lexicographic_encode() >= 0u64.lexicographic_encode());
  }

  // `lexicographic_decode`
  for _ in 0 .. 100 {
    let value = OsRng.next_u64();
    assert_eq!(u64::lexicographic_decode(value.lexicographic_encode()), value);
  }

  // Fuzz test the ordinality
  for _ in 0 .. 100 {
    let a = OsRng.next_u64();
    let b = OsRng.next_u64();
    assert_eq!(a.cmp(&b), a.lexicographic_encode().cmp(&b.lexicographic_encode()));
  }
}

#[test]
fn lexicographic_reverse() {
  use rand_core::{RngCore as _, OsRng};

  for _ in 0 .. 100 {
    let a = OsRng.next_u64();
    let b = loop {
      let b = OsRng.next_u64();
      if a != b {
        break b;
      }
    };
    let a_enc = a.lexicographic_encode();
    let b_enc = b.lexicographic_encode();
    assert_eq!(a_enc, a_enc);
    assert_eq!(a.cmp(&b), a_enc.cmp(&b_enc));

    assert_eq!(a.cmp(&b).reverse(), reverse(a_enc).cmp(&reverse(b_enc)));

    // This should be a bijective encoding
    assert_eq!(reverse(reverse(a_enc)), a_enc);
    assert_eq!(reverse(reverse(b_enc)), b_enc);
    assert_eq!(LexicographicReverse::<u64>::from_encoding(a.lexicographic_encode()).into(), a);
    assert_eq!(LexicographicReverse::<u64>::from_encoding(b.lexicographic_encode()).into(), b);
    assert_eq!(LexicographicReverse::from(&a).into(), a);
    assert_eq!(LexicographicReverse::from(&b).into(), b);
  }
}
