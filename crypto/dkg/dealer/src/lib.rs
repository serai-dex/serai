#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use core::ops::Deref as _;
use std_shims::{vec::Vec, collections::HashMap};

use zeroize::{Zeroize, Zeroizing};
use rand_core::{RngCore, CryptoRng};

use ciphersuite::{
  group::ff::{Field as _, PrimeField},
  GroupIo, Id,
};
pub use dkg::*;

/// Create a key via a dealer key generation protocol.
pub fn key_gen<R: RngCore + CryptoRng, C: GroupIo + Id>(
  rng: &mut R,
  threshold: u16,
  participants: u16,
) -> Result<HashMap<Participant, ThresholdKeys<C>>, DkgError> {
  let mut coefficients = Vec::with_capacity(usize::from(participants));
  // `.max(1)` so we always generate the 0th coefficient which we'll share
  for _ in 0 .. threshold.max(1) {
    coefficients.push(Zeroizing::new(C::F::random(&mut *rng)));
  }

  fn polynomial<F: PrimeField + Zeroize>(
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

  let group_key = C::generator() * coefficients[0].deref();
  let mut secret_shares = HashMap::with_capacity(usize::from(participants));
  let mut verification_shares = HashMap::with_capacity(usize::from(participants));
  for i in 1 ..= participants {
    let i = Participant::new(i).expect("non-zero u16 wasn't a valid Participant index");
    let secret_share = polynomial(&coefficients, i);
    secret_shares.insert(i, secret_share.clone());
    verification_shares.insert(i, C::generator() * *secret_share);
  }

  let mut res = HashMap::with_capacity(usize::from(participants));
  for (i, secret_share) in secret_shares {
    let keys = ThresholdKeys::new(
      ThresholdParams::new(threshold, participants, i)?,
      Interpolation::Lagrange,
      secret_share,
      verification_shares.clone(),
    )?;
    debug_assert_eq!(keys.group_key(), group_key);
    res.insert(i, keys);
  }
  Ok(res)
}
