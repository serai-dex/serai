use rand_core::OsRng;

use group::ff::Field;
use k256::Scalar;

use crate::Signature;

#[test]
fn test_zero_challenge() {
  assert!(Signature::new(Scalar::ZERO, Scalar::random(&mut OsRng)).is_none());
}

#[test]
fn test_signature_serialization() {
  let c = Scalar::random(&mut OsRng);
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
