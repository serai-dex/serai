use std::{marker::PhantomData, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use group::Group;

use ciphersuite::Ciphersuite;

use crate::{
  promote::{GeneratorPromotion, GeneratorProof},
  tests::{clone_without, key_gen, recover_key},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
struct AltGenerator<C: Ciphersuite> {
  _curve: PhantomData<C>,
}

impl<C: Ciphersuite> Ciphersuite for AltGenerator<C> {
  type F = C::F;
  type G = C::G;
  type H = C::H;

  const ID: &'static [u8] = b"Alternate Ciphersuite";

  fn generator() -> Self::G {
    C::G::generator() * <C as Ciphersuite>::hash_to_F(b"DKG Promotion Test", b"generator")
  }

  fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
    <C as Ciphersuite>::hash_to_F(dst, data)
  }
}

// Test promotion of threshold keys to another generator
pub(crate) fn test_generator_promotion<R: RngCore + CryptoRng, C: Ciphersuite>(rng: &mut R) {
  let keys = key_gen::<_, C>(&mut *rng);

  let mut promotions = HashMap::new();
  let mut proofs = HashMap::new();
  for (i, keys) in &keys {
    let (promotion, proof) =
      GeneratorPromotion::<_, AltGenerator<C>>::promote(&mut *rng, keys.clone());
    promotions.insert(*i, promotion);
    proofs.insert(*i, GeneratorProof::<C>::read::<&[u8]>(&mut proof.serialize().as_ref()).unwrap());
  }

  let new_group_key = AltGenerator::<C>::generator() * recover_key(&keys);
  for (i, promoting) in promotions.drain() {
    let promoted = promoting.complete(&clone_without(&proofs, &i)).unwrap();
    assert_eq!(keys[&i].params(), promoted.params());
    assert_eq!(keys[&i].secret_share(), promoted.secret_share());
    assert_eq!(new_group_key, promoted.group_key());
    for (l, verification_share) in promoted.verification_shares() {
      assert_eq!(AltGenerator::<C>::generator() * keys[&l].secret_share(), verification_share);
    }
  }
}
