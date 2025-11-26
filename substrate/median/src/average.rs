use core::cmp::Ord;

/// A trait to take the average of two values
pub trait Average {
  /// Calculate the average of two values.
  fn average(value: Self, other: Self) -> Self;
}

macro_rules! impl_prim_uint {
  ($type: ident) => {
    impl Average for $type {
      /// This rounds as integer division does: by flooring the result.
      fn average(value: Self, other: Self) -> Self {
        /*
          Since `value + other` may overflow, without promotion to a wider integer, we perform the
          halving as the first operation. Then we add back the truncated bit as necessary. This
          methodology doesn't overflow and doesn't require the existence of a wider integer type.
        */
        (value / 2) + (other / 2) + (value & other & 1)
      }
    }
  };
}
impl_prim_uint!(u8);
impl_prim_uint!(u16);
impl_prim_uint!(u32);
impl_prim_uint!(u64);
impl_prim_uint!(u128);

#[test]
fn average() {
  use rand_core::{RngCore, OsRng};

  // Basic sanity checks
  {
    assert_eq!(u64::average(0, 0), 0);
    assert_eq!(u64::average(0, 1), 0);
    assert_eq!(u64::average(0, 2), 1);
    assert_eq!(u64::average(u64::MAX, u64::MAX), u64::MAX);
    assert_eq!(u64::average(u64::MAX - 1, u64::MAX), u64::MAX - 1);
    assert_eq!(u64::average(u64::MAX - 2, u64::MAX), u64::MAX - 1);
    assert_eq!(u64::average(u64::MAX - 1, u64::MAX - 1), u64::MAX - 1);
  }

  // Fuzz test the function
  for _ in 0 .. 100 {
    let a = OsRng.next_u64();
    let b = OsRng.next_u64();
    assert_eq!(u64::average(a, b), u64::try_from((u128::from(a) + u128::from(b)) / 2).unwrap());
  }
}
