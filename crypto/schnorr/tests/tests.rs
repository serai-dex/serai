use rand_core::OsRng;

use blake2::{Digest, Blake2b512};

use curve::group::{ff::Field, Group, GroupEncoding};
use dalek_ff_group::{Scalar, RistrettoPoint};

#[cfg(feature = "batch")]
use multiexp::BatchVerifier;

use modular_schnorr::{Hram, Signature, Schnorr, ClassicalSchnorr};

const MSG: &[u8] = b"Hello, World";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SimpleHram;
impl Hram<RistrettoPoint> for SimpleHram {
  #[allow(non_snake_case)]
  fn hram(R: RistrettoPoint, A: RistrettoPoint, m: &[u8]) -> Scalar {
    Scalar::from_hash(Blake2b512::new().chain_update(&[&R.to_bytes(), &A.to_bytes(), m].concat()))
  }
}

#[test]
fn sign_verify() {
  let key = Scalar::random(&mut OsRng);
  assert!(Schnorr::<RistrettoPoint, SimpleHram>::sign(&mut OsRng, key, MSG)
    .verify(RistrettoPoint::generator() * key, MSG));
  assert!(ClassicalSchnorr::<RistrettoPoint, SimpleHram>::sign(&mut OsRng, key, MSG)
    .verify(RistrettoPoint::generator() * key, MSG));
}

/*
#[test]
fn conversion() {
  let key = Scalar::random(&mut OsRng);
  let pub = RistrettoPoint::generator() * key;
  let sig = Schnorr::<RistrettoPoint, SimpleHram>::sign(&mut OsRng, key, MSG);
  assert!(sig.verify(public_key, MSG));

  let classical = ClassicalSchnorr::from(sig);
  assert!(classical.verify(public_key, MSG));
  let back = Schnorr::from(classical);
  assert!(back.verify(public_key, MSG));
  assert_eq!(sig, back);
}
*/

#[test]
fn zero() {
  // True zero should pass for any message
  assert!(Schnorr::<RistrettoPoint, SimpleHram>::new(RistrettoPoint::identity(), Scalar::zero())
    .verify(RistrettoPoint::identity(), MSG));
  // ClassicalSchnorr doesn't have a "true zero" as c is a hash output
  // While it's possible to craft a c for a 0 nonce, that's just checking a 0 nonce

  // But not for an actual key
  assert!(!Schnorr::<RistrettoPoint, SimpleHram>::new(RistrettoPoint::identity(), Scalar::zero())
    .verify(RistrettoPoint::random(&mut OsRng), MSG));
  assert!(!ClassicalSchnorr::<RistrettoPoint, SimpleHram>::new(Scalar::zero(), Scalar::zero())
    .verify(RistrettoPoint::random(&mut OsRng), MSG));
}

#[test]
fn random_fails() {
  assert!(!Schnorr::<RistrettoPoint, SimpleHram>::new(
    RistrettoPoint::random(&mut OsRng),
    Scalar::random(&mut OsRng)
  )
  .verify(RistrettoPoint::random(&mut OsRng), MSG));

  assert!(!ClassicalSchnorr::<RistrettoPoint, SimpleHram>::new(
    Scalar::random(&mut OsRng),
    Scalar::random(&mut OsRng)
  )
  .verify(RistrettoPoint::random(&mut OsRng), MSG));
}

#[cfg(feature = "serialize")]
#[test]
fn serialize() {
  let sig =
    Schnorr::<RistrettoPoint, SimpleHram>::sign(&mut OsRng, Scalar::random(&mut OsRng), MSG);
  let mut serialized = vec![];
  sig.serialize(&mut serialized).unwrap();
  assert_eq!(sig, Schnorr::deserialize(&mut std::io::Cursor::new(serialized)).unwrap());

  let sig = ClassicalSchnorr::<RistrettoPoint, SimpleHram>::sign(
    &mut OsRng,
    Scalar::random(&mut OsRng),
    MSG,
  );
  let mut serialized = vec![];
  sig.serialize(&mut serialized).unwrap();
  assert_eq!(sig, ClassicalSchnorr::deserialize(&mut std::io::Cursor::new(serialized)).unwrap());
}

#[cfg(feature = "batch")]
#[test]
fn batch_verify() {
  // Create 5 signatures
  let mut keys = vec![];
  let mut sigs = vec![];
  let mut verifier = BatchVerifier::new(5);
  for i in 0 .. 5 {
    keys.push(Scalar::random(&mut OsRng));
    sigs.push(Schnorr::<RistrettoPoint, SimpleHram>::sign(
      &mut OsRng,
      keys[i],
      &[MSG, &i.to_le_bytes()].concat(),
    ));
    sigs[i].queue_batch_verification(
      &mut verifier,
      i,
      RistrettoPoint::generator() * keys[i],
      &[MSG, &i.to_le_bytes()].concat(),
    );
  }
  assert!(verifier.verify_vartime(&mut OsRng));

  // Test invalid signatures don't batch verify
  Schnorr::<RistrettoPoint, SimpleHram>::new(
    RistrettoPoint::random(&mut OsRng),
    Scalar::random(&mut OsRng),
  )
  .queue_batch_verification(&mut verifier, 5, RistrettoPoint::random(&mut OsRng), MSG);
  assert_eq!(verifier.verify_vartime_with_vartime_blame(&mut OsRng).unwrap_err(), 5);
}
