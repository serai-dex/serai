use std_shims::prelude::*;

use rand_core::{RngCore as _, OsRng};

use group::ff::{Field as _, PrimeField as _};
use k256::Scalar;

use crate::Signature;

#[test]
fn test_zero_challenge() {
  assert!(Signature::new([0; 32], Scalar::random(&mut OsRng)).is_none());

  // Test the modulus, which is congruent to zero modulo itself
  assert!(Signature::new(
    {
      let modulus_minus_one = (-Scalar::ONE).to_repr();
      let mut modulus = modulus_minus_one;
      modulus[31] = modulus_minus_one[31].checked_add(1).unwrap();
      modulus.into()
    },
    Scalar::random(&mut OsRng)
  )
  .is_none());
}

#[test]
fn test_signature_serialization() {
  let mut c = [0; 32];
  OsRng.fill_bytes(&mut c);
  let c = c;
  let s = Scalar::random(&mut OsRng);
  let sig = Signature::new(c, s).unwrap();
  assert_eq!(sig.c(), c);
  assert_eq!(sig.s(), s);

  let sig_bytes = sig.to_bytes();
  assert_eq!(Signature::from_bytes(sig_bytes).unwrap(), sig);

  {
    let mut sig_written_bytes = vec![];
    sig.write(&mut sig_written_bytes).unwrap();
    assert_eq!(sig_bytes.as_slice(), &sig_written_bytes);
  }

  let mut sig_read_slice = sig_bytes.as_slice();
  assert_eq!(Signature::read(&mut sig_read_slice).unwrap(), sig);
  assert!(sig_read_slice.is_empty());
}
