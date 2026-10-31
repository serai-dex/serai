#[derive(Clone, Copy, PartialEq, Eq)]
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
