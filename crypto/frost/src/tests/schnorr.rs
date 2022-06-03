use std::{marker::PhantomData, rc::Rc, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use ff::Field;

use crate::{
  Curve, MultisigKeys, schnorr::{self, SchnorrSignature}, algorithm::{Hram, Schnorr},
  tests::{key_gen, algorithm_machines, sign as sign_test}
};

pub(crate) fn core_sign<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let private_key = C::F::random(&mut *rng);
  let nonce = C::F::random(&mut *rng);
  let challenge = C::F::random(rng); // Doesn't bother to craft an HRAM
  assert!(
    schnorr::verify::<C>(
      C::generator_table() * private_key,
      challenge,
      &schnorr::sign(private_key, nonce, challenge)
    )
  );
}

// The above sign function verifies signing works
// This verifies invalid signatures don't pass, using zero signatures, which should effectively be
// random
pub(crate) fn core_verify<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  assert!(
    !schnorr::verify::<C>(
      C::generator_table() * C::F::random(&mut *rng),
      C::F::random(rng),
      &SchnorrSignature { R: C::generator_table() * C::F::zero(), s: C::F::zero() }
    )
  );
}

pub(crate) fn core_batch_verify<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  // Create 5 signatures
  let mut keys = vec![];
  let mut challenges = vec![];
  let mut sigs = vec![];
  for i in 0 .. 5 {
    keys.push(C::F::random(&mut *rng));
    challenges.push(C::F::random(&mut *rng));
    sigs.push(schnorr::sign::<C>(keys[i], C::F::random(&mut *rng), challenges[i]));
  }

  // Batch verify
  let triplets = (0 .. 5).map(
    |i| (u16::try_from(i + 1).unwrap(), C::generator_table() * keys[i], challenges[i], sigs[i])
  ).collect::<Vec<_>>();
  schnorr::batch_verify(rng, &triplets).unwrap();

  // Shift 1 from s from one to another and verify it fails
  // This test will fail if unique factors aren't used per-signature, hence its inclusion
  {
    let mut triplets = triplets.clone();
    triplets[1].3.s += C::F::one();
    triplets[2].3.s -= C::F::one();
    if let Err(blame) = schnorr::batch_verify(rng, &triplets) {
      assert_eq!(blame, 2);
    } else {
      assert!(false);
    }
  }

  // Make sure a completely invalid signature fails when included
  for i in 0 .. 5 {
    let mut triplets = triplets.clone();
    triplets[i].3.s = C::F::random(&mut *rng);
    if let Err(blame) = schnorr::batch_verify(rng, &triplets) {
      assert_eq!(blame, u16::try_from(i + 1).unwrap());
    } else {
      assert!(false);
    }
  }
}

fn sign_core<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R,
  group_key: C::G,
  keys: &HashMap<u16, Rc<MultisigKeys<C>>>
) {
  const MESSAGE: &'static [u8] = b"Hello, World!";

  let machines = algorithm_machines(rng, Schnorr::<C, TestHram<C>>::new(), keys);
  let sig = sign_test(&mut *rng, machines, MESSAGE);
  assert!(schnorr::verify(group_key, TestHram::<C>::hram(&sig.R, &group_key, MESSAGE), &sig));
}

#[derive(Clone)]
pub struct TestHram<C: Curve> {
  _curve: PhantomData<C>
}
impl<C: Curve> Hram<C> for TestHram<C> {
  #[allow(non_snake_case)]
  fn hram(R: &C::G, A: &C::G, m: &[u8]) -> C::F {
    C::hash_to_F(b"challenge", &[&C::G_to_bytes(R), &C::G_to_bytes(A), m].concat())
  }
}

fn sign<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let keys = key_gen::<_, C>(&mut *rng);
  sign_core(rng, keys[&1].group_key(), &keys);
}

fn sign_with_offset<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let mut keys = key_gen::<_, C>(&mut *rng);
  let group_key = keys[&1].group_key();

  let offset = C::hash_to_F(b"FROST Test sign_with_offset", b"offset");
  for i in 1 ..= u16::try_from(keys.len()).unwrap() {
    keys.insert(i, Rc::new(keys[&i].offset(offset)));
  }
  let offset_key = group_key + (C::generator_table() * offset);

  sign_core(rng, offset_key, &keys);
}

pub fn test_schnorr<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  // Test Schnorr signatures work as expected
  // This is a bit unnecessary, as they should for any valid curve, yet this establishes sanity
  core_sign::<_, C>(rng);
  core_verify::<_, C>(rng);
  core_batch_verify::<_, C>(rng);

  // Test Schnorr signatures under FROST
  sign::<_, C>(rng);
  sign_with_offset::<_, C>(rng);
}
