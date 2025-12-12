use std_shims::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::OsRng;

use dalek_ff_group::Ristretto;
use ciphersuite::WrappedGroup;

use dkg_recovery::recover_key;
use crate::*;

/// Tests MuSig key generation.
#[test]
pub fn test_musig() {
  const PARTICIPANTS: u16 = 5;

  let mut keys = vec![];
  let mut pub_keys = vec![];
  for _ in 0 .. PARTICIPANTS {
    let key = Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut OsRng));
    pub_keys.push(<Ristretto as WrappedGroup>::generator() * *key);
    keys.push(key);
  }

  const CONTEXT: [u8; 32] = *b"MuSig Test                      ";

  // Empty signing set
  musig::<Ristretto>(CONTEXT, Zeroizing::new(<Ristretto as WrappedGroup>::F::ZERO), &[])
    .unwrap_err();
  // Signing set we're not part of
  musig::<Ristretto>(
    CONTEXT,
    Zeroizing::new(<Ristretto as WrappedGroup>::F::ZERO),
    &[<Ristretto as WrappedGroup>::generator()],
  )
  .unwrap_err();

  // Test with n keys
  {
    let mut created_keys = HashMap::new();
    let mut verification_shares = HashMap::new();
    let group_key = musig_key::<Ristretto>(CONTEXT, &pub_keys).unwrap();
    for (i, key) in keys.iter().enumerate() {
      let these_keys = musig::<Ristretto>(CONTEXT, key.clone(), &pub_keys).unwrap();
      assert_eq!(these_keys.params().t(), PARTICIPANTS);
      assert_eq!(these_keys.params().n(), PARTICIPANTS);
      assert_eq!(usize::from(u16::from(these_keys.params().i())), i + 1);

      verification_shares.insert(
        these_keys.params().i(),
        <Ristretto as WrappedGroup>::generator() * **these_keys.original_secret_share(),
      );

      assert_eq!(these_keys.group_key(), group_key);

      created_keys.insert(these_keys.params().i(), these_keys);
    }

    for keys in created_keys.values() {
      for (l, verification_share) in &verification_shares {
        assert_eq!(keys.original_verification_share(*l), *verification_share);
      }
    }

    assert_eq!(
      <Ristretto as WrappedGroup>::generator() *
        *recover_key(&created_keys.values().cloned().collect::<Vec<_>>()).unwrap(),
      group_key
    );
  }
}
