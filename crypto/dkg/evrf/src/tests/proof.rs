use std::time::Instant;

use rand_core::OsRng;

use zeroize::Zeroizing;

use ciphersuite::{
  group::{ff::Field, Group},
  Ciphersuite,
};

use generalized_bulletproofs::{Generators, tests::insecure_test_generators};

use crate::{
  Curves, Ristretto,
  proof::*,
  tests::{THRESHOLD, PARTICIPANTS},
};

fn proof<C: Curves>() {
  let generators = insecure_test_generators(&mut OsRng, 2048).unwrap();
  let embedded_private_key =
    Zeroizing::new(<C::EmbeddedCurve as Ciphersuite>::F::random(&mut OsRng));
  let ecdh_public_keys: [_; PARTICIPANTS as usize] =
    core::array::from_fn(|_| <C::EmbeddedCurve as Ciphersuite>::G::random(&mut OsRng));
  let time = Instant::now();
  let res = Proof::<C>::prove(
    &mut OsRng,
    &generators,
    [0; 32],
    THRESHOLD.into(),
    &ecdh_public_keys,
    &embedded_private_key,
  )
  .unwrap();
  println!("Proving time: {:?}", time.elapsed());

  let time = Instant::now();
  let mut verifier = Generators::batch_verifier();
  Proof::<C>::verify(
    &mut OsRng,
    &generators,
    &mut verifier,
    [0; 32],
    THRESHOLD.into(),
    &ecdh_public_keys,
    C::EmbeddedCurve::generator() * *embedded_private_key,
    &res.proof,
  )
  .unwrap();
  assert!(generators.verify(verifier));
  println!("Verifying time: {:?}", time.elapsed());
}

#[test]
fn ristretto_proof() {
  proof::<Ristretto>();
}
