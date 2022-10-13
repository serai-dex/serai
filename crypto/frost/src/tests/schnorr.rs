use std::{marker::PhantomData, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use group::{ff::Field, Group, GroupEncoding};

use crate::{
  Curve, FrostKeys,
  schnorr::{self, SchnorrSignature},
  algorithm::{Hram, Schnorr},
  tests::{key_gen, algorithm_machines, sign as sign_test},
};

pub(crate) fn core_sign<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let private_key = C::random_F(&mut *rng);
  let nonce = C::random_F(&mut *rng);
  let challenge = C::random_F(rng); // Doesn't bother to craft an HRAm
  assert!(schnorr::verify::<C>(
    C::generator() * private_key,
    challenge,
    &schnorr::sign(private_key, nonce, challenge)
  ));
}

// The above sign function verifies signing works
// This verifies invalid signatures don't pass, using zero signatures, which should effectively be
// random
pub(crate) fn core_verify<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  assert!(!schnorr::verify::<C>(
    C::generator() * C::random_F(&mut *rng),
    C::random_F(rng),
    &SchnorrSignature { R: C::G::identity(), s: C::F::zero() }
  ));
}

pub(crate) fn core_batch_verify<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  // Create 5 signatures
  let mut keys = vec![];
  let mut challenges = vec![];
  let mut sigs = vec![];
  for i in 0 .. 5 {
    keys.push(C::random_F(&mut *rng));
    challenges.push(C::random_F(&mut *rng));
    sigs.push(schnorr::sign::<C>(keys[i], C::random_F(&mut *rng), challenges[i]));
  }

  // Batch verify
  let triplets = (0 .. 5)
    .map(|i| (u16::try_from(i + 1).unwrap(), C::generator() * keys[i], challenges[i], sigs[i]))
    .collect::<Vec<_>>();
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
      panic!("batch verification considered a malleated signature valid");
    }
  }

  // Make sure a completely invalid signature fails when included
  for i in 0 .. 5 {
    let mut triplets = triplets.clone();
    triplets[i].3.s = C::random_F(&mut *rng);
    if let Err(blame) = schnorr::batch_verify(rng, &triplets) {
      assert_eq!(blame, u16::try_from(i + 1).unwrap());
    } else {
      panic!("batch verification considered an invalid signature valid");
    }
  }
}

pub(crate) fn sign_core<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R,
  keys: &HashMap<u16, FrostKeys<C>>,
) {
  const MESSAGE: &[u8] = b"Hello, World!";

  let machines = algorithm_machines(rng, Schnorr::<C, TestHram<C>>::new(), keys);
  let sig = sign_test(&mut *rng, machines, MESSAGE);

  let group_key = keys[&1].group_key();
  assert!(schnorr::verify(group_key, TestHram::<C>::hram(&sig.R, &group_key, MESSAGE), &sig));
}

#[derive(Clone)]
pub struct TestHram<C: Curve> {
  _curve: PhantomData<C>,
}
impl<C: Curve> Hram<C> for TestHram<C> {
  #[allow(non_snake_case)]
  fn hram(R: &C::G, A: &C::G, m: &[u8]) -> C::F {
    C::hash_to_F(b"challenge", &[R.to_bytes().as_ref(), A.to_bytes().as_ref(), m].concat())
  }
}

fn sign<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let keys = key_gen::<_, C>(&mut *rng);
  sign_core(rng, &keys);
}

fn sign_with_offset<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let mut keys = key_gen::<_, C>(&mut *rng);
  let group_key = keys[&1].group_key();

  let offset = C::hash_to_F(b"FROST Test sign_with_offset", b"offset");
  for i in 1 ..= u16::try_from(keys.len()).unwrap() {
    keys.insert(i, keys[&i].offset(offset));
  }
  let offset_key = group_key + (C::generator() * offset);
  assert_eq!(keys[&1].group_key(), offset_key);

  sign_core(rng, &keys);
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
