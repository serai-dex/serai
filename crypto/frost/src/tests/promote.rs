use std::{marker::PhantomData, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use group::Group;

use ciphersuite::Ciphersuite;

use crate::{
  Curve, // FrostKeys,
  promote::{GeneratorPromotion /* CurvePromote */},
  tests::{clone_without, key_gen, schnorr::sign_core},
};

/*
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
struct AltFunctions<C: Curve> {
  _curve: PhantomData<C>,
}

impl<C: Curve> Curve for AltFunctions<C> {
  type F = C::F;
  type G = C::G;

  const ID: &'static [u8] = b"alt_functions";

  fn generator() -> Self::G {
    C::generator()
  }

  fn hash_msg(msg: &[u8]) -> Vec<u8> {
    C::hash_msg(&[msg, b"alt"].concat())
  }

  fn hash_binding_factor(binding: &[u8]) -> Self::F {
    C::hash_to_F(b"rho_alt", binding)
  }

  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
    C::hash_to_F(&[dst, b"alt"].concat(), msg)
  }
}

// Test promotion of FROST keys to another set of functions for interoperability
fn test_ciphersuite_promotion<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let keys = key_gen::<_, C>(&mut *rng);
  for keys in keys.values() {
    let promoted: FrostKeys<AltFunctions<C>> = keys.clone().promote();
    // Verify equivalence via their serializations, minus the ID's length and ID itself
    assert_eq!(
      keys.serialize()[(4 + C::ID.len()) ..],
      promoted.serialize()[(4 + AltFunctions::<C>::ID.len()) ..]
    );
  }
}
*/

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
struct AltGenerator<C: Curve> {
  _curve: PhantomData<C>,
}

impl<C: Curve> Ciphersuite for AltGenerator<C> {
  type F = C::F;
  type G = C::G;
  type H = C::H;

  const ID: &'static [u8] = b"alt_generator";

  fn generator() -> Self::G {
    C::G::generator() * <C as Curve>::hash_to_F(b"FROST_tests", b"generator")
  }

  fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
    <C as Curve>::hash_to_F(&[b"FROST_tests_alt", dst].concat(), data)
  }
}

impl<C: Curve> Curve for AltGenerator<C> {
  const CONTEXT: &'static [u8] = b"alt context";
}

// Test promotion of FROST keys to another generator
fn test_generator_promotion<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  // A seeded RNG can theoretically generate for C1 and C2, verifying promotion that way?
  // TODO
  let keys = key_gen::<_, C>(&mut *rng);

  let mut promotions = HashMap::new();
  let mut proofs = HashMap::new();
  for (i, keys) in &keys {
    let promotion = GeneratorPromotion::<_, AltGenerator<C>>::promote(&mut *rng, keys.clone());
    promotions.insert(*i, promotion.0);
    proofs.insert(*i, promotion.1);
  }

  let mut new_keys = HashMap::new();
  let mut group_key = None;
  let mut verification_shares = None;
  for (i, promoting) in promotions.drain() {
    let promoted = promoting.complete(&clone_without(&proofs, &i)).unwrap();
    assert_eq!(keys[&i].params(), promoted.params());
    assert_eq!(keys[&i].secret_share(), promoted.secret_share());

    if group_key.is_none() {
      group_key = Some(keys[&i].group_key());
      verification_shares = Some(keys[&i].verification_shares());
    }
    assert_eq!(keys[&i].group_key(), group_key.unwrap());
    assert_eq!(&keys[&i].verification_shares(), verification_shares.as_ref().unwrap());

    new_keys.insert(i, promoted);
  }

  // Sign with the keys to ensure their integrity
  sign_core(rng, &new_keys);
}

pub fn test_promotion<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  // test_ciphersuite_promotion::<_, C>(rng);
  test_generator_promotion::<_, C>(rng);
}
