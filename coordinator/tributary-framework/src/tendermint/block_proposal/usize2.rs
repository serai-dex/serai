#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct Usize2 {
  lo: usize,
  hi: usize,
}

impl core::ops::Add<usize> for Usize2 {
  type Output = Self;
  fn add(mut self, rhs: usize) -> Self {
    let carry;
    (self.lo, carry) = self.lo.overflowing_add(rhs);
    self.hi += usize::from(u8::from(carry));
    self
  }
}

impl Usize2 {
  pub(super) const ZERO: Self = Self { lo: 0, hi: 0 };

  pub(super) fn checked_sub(self, rhs: usize) -> Option<Self> {
    let (lo, carry) = self.lo.overflowing_sub(rhs);
    self.hi.checked_sub(usize::from(u8::from(carry))).map(|hi| Self { lo, hi })
  }
}

#[test]
fn usize2() {
  assert_eq!((Usize2::ZERO + 1).checked_sub(1).unwrap(), Usize2::ZERO);
  assert_eq!((Usize2::ZERO + usize::MAX + 1), Usize2 { hi: 1, lo: 0 });
  assert_eq!((Usize2::ZERO + usize::MAX + 1 + usize::MAX + 1 + 1), Usize2 { hi: 2, lo: 1 });
  assert_eq!(
    (Usize2::ZERO + usize::MAX + 1 + usize::MAX + 1 + 1).checked_sub(2).unwrap(),
    Usize2 { hi: 1, lo: usize::MAX }
  );
  assert_eq!(Usize2::ZERO.checked_sub(0).unwrap(), Usize2::ZERO);
  assert_eq!(Usize2::ZERO.checked_sub(1), None);
}
