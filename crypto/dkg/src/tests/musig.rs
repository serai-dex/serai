use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use ciphersuite::{group::ff::Field, Ciphersuite};

use crate::{
  ThresholdKeys,
  musig::{musig_key, musig},
  tests::{PARTICIPANTS, recover_key},
};

/// Tests MuSig key generation.
pub fn test_musig<R: RngCore + CryptoRng, C: Ciphersuite>(rng: &mut R) {
  let mut keys = vec![];
  let mut pub_keys = vec![];
  for _ in 0 .. PARTICIPANTS {
    let key = Zeroizing::new(C::F::random(&mut *rng));
    pub_keys.push(C::generator() * *key);
    keys.push(key);
  }

  const CONTEXT: &[u8] = b"MuSig Test";

  // Empty signing set
  assert!(musig::<C>(CONTEXT, &Zeroizing::new(C::F::ZERO), &[]).is_err());
  // Signing set we're not part of
  assert!(musig::<C>(CONTEXT, &Zeroizing::new(C::F::ZERO), &[C::generator()]).is_err());

  // Test with n keys
  {
    let mut created_keys = HashMap::new();
    let mut verification_shares = HashMap::new();
    let group_key = musig_key::<C>(CONTEXT, &pub_keys).unwrap();
    for (i, key) in keys.iter().enumerate() {
      let these_keys = musig::<C>(CONTEXT, key, &pub_keys).unwrap();
      assert_eq!(these_keys.params().t(), PARTICIPANTS);
      assert_eq!(these_keys.params().n(), PARTICIPANTS);
      assert_eq!(usize::from(these_keys.params().i().0), i + 1);

      verification_shares
        .insert(these_keys.params().i(), C::generator() * **these_keys.secret_share());

      assert_eq!(these_keys.group_key(), group_key);

      created_keys.insert(these_keys.params().i(), ThresholdKeys::new(these_keys));
    }

    for keys in created_keys.values() {
      assert_eq!(keys.verification_shares(), verification_shares);
    }

    assert_eq!(C::generator() * recover_key(&created_keys), group_key);
  }
}

#[test]
fn musig_literal() {
  test_musig::<_, ciphersuite::Ristretto>(&mut rand_core::OsRng)
}
