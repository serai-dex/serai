use core::ops::Deref;

use zeroize::{Zeroize, Zeroizing};
use rand_core::{RngCore, CryptoRng};

use ciphersuite::{
  group::{ff::PrimeField, Group, GroupEncoding},
  GroupIo,
};

use dkg::Participant;

/// Sample a random, unbiased point on the elliptic curve with an unknown discrete logarithm.
///
/// This keeps it simple by using rejection sampling.
pub(crate) fn sample_point<C: GroupIo>(rng: &mut (impl RngCore + CryptoRng)) -> C::G {
  let mut repr = <C::G as GroupEncoding>::Repr::default();
  loop {
    rng.fill_bytes(repr.as_mut());
    if let Ok(point) = C::read_G(&mut repr.as_ref()) {
      if bool::from(!point.is_identity()) {
        return point;
      }
    }
  }
}

pub(super) fn polynomial<F: PrimeField + Zeroize>(
  coefficients: &[Zeroizing<F>],
  l: Participant,
) -> Zeroizing<F> {
  let l = F::from(u64::from(u16::from(l)));
  // This should never be reached since Participant is explicitly non-zero
  assert!(l != F::ZERO, "zero participant passed to polynomial");
  let mut share = Zeroizing::new(F::ZERO);
  for (idx, coefficient) in coefficients.iter().rev().enumerate() {
    *share += coefficient.deref();
    if idx != (coefficients.len() - 1) {
      *share *= l;
    }
  }
  share
}
