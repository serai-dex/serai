use core::marker::PhantomData;
use std::collections::HashMap;

use zeroize::{Zeroize, Zeroizing};
use rand_core::OsRng;

use ciphersuite::{
  group::{ff::Field, Group},
  Ciphersuite, Ristretto,
};

use dkg::*;
use dkg_recovery::recover_key;
use crate::{GeneratorPromotion, GeneratorProof};

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

  fn reduce_512(scalar: [u8; 64]) -> Self::F {
    <C as Ciphersuite>::reduce_512(scalar)
  }

  fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
    <C as Ciphersuite>::hash_to_F(dst, data)
  }
}

/// Clone a map without a specific value.
pub fn clone_without<K: Clone + core::cmp::Eq + core::hash::Hash, V: Clone>(
  map: &HashMap<K, V>,
  without: &K,
) -> HashMap<K, V> {
  let mut res = map.clone();
  res.remove(without).unwrap();
  res
}

// Test promotion of threshold keys to another generator
#[test]
fn test_generator_promotion() {
  // Generate a set of `ThresholdKeys`
  const PARTICIPANTS: u16 = 5;
  let keys: [ThresholdKeys<_>; PARTICIPANTS as usize] = {
    let shares: [<Ristretto as Ciphersuite>::F; PARTICIPANTS as usize] =
      core::array::from_fn(|_| <Ristretto as Ciphersuite>::F::random(&mut OsRng));
    let verification_shares = (0 .. PARTICIPANTS)
      .map(|i| {
        (
          Participant::new(i + 1).unwrap(),
          <Ristretto as Ciphersuite>::generator() * shares[usize::from(i)],
        )
      })
      .collect::<HashMap<_, _>>();
    core::array::from_fn(|i| {
      ThresholdKeys::new(
        ThresholdParams::new(
          PARTICIPANTS,
          PARTICIPANTS,
          Participant::new(u16::try_from(i + 1).unwrap()).unwrap(),
        )
        .unwrap(),
        Interpolation::Constant(vec![<Ristretto as Ciphersuite>::F::ONE; PARTICIPANTS as usize]),
        Zeroizing::new(shares[i]),
        verification_shares.clone(),
      )
      .unwrap()
    })
  };

  // Perform the promotion
  let mut promotions = HashMap::new();
  let mut proofs = HashMap::new();
  for keys in &keys {
    let i = keys.params().i();
    let (promotion, proof) =
      GeneratorPromotion::<_, AltGenerator<Ristretto>>::promote(&mut OsRng, keys.clone());
    promotions.insert(i, promotion);
    proofs.insert(
      i,
      GeneratorProof::<Ristretto>::read::<&[u8]>(&mut proof.serialize().as_ref()).unwrap(),
    );
  }

  // Complete the promotion, and verify it worked
  let new_group_key = AltGenerator::<Ristretto>::generator() * *recover_key(&keys).unwrap();
  for (i, promoting) in promotions.drain() {
    let promoted = promoting.complete(&clone_without(&proofs, &i)).unwrap();
    assert_eq!(keys[usize::from(u16::from(i) - 1)].params(), promoted.params());
    assert_eq!(
      keys[usize::from(u16::from(i) - 1)].original_secret_share(),
      promoted.original_secret_share()
    );
    assert_eq!(new_group_key, promoted.group_key());
    for l in 0 .. PARTICIPANTS {
      let verification_share =
        promoted.original_verification_share(Participant::new(l + 1).unwrap());
      assert_eq!(
        AltGenerator::<Ristretto>::generator() * **keys[usize::from(l)].original_secret_share(),
        verification_share
      );
    }
  }
}
