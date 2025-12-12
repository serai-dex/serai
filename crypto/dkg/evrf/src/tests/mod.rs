use std_shims::{prelude::*, collections::HashMap};

use zeroize::Zeroizing;
use rand_core::OsRng;
use rand::seq::SliceRandom;

use ciphersuite::{group::ff::Field, WrappedGroup};
use embedwards25519::Embedwards25519;

use dkg_recovery::recover_key;
use crate::{Participant, Curves, Generators, VerifyResult, Dkg, Ed25519};

mod proof;

const THRESHOLD: u16 = 3;
const PARTICIPANTS: u16 = 5;

#[test]
fn dkg() {
  let generators = Generators::<Ed25519>::new(THRESHOLD, PARTICIPANTS);
  let context = [0; 32];

  let mut priv_keys = vec![];
  let mut pub_keys = vec![];
  for i in 0 .. PARTICIPANTS {
    let priv_key = <Embedwards25519 as WrappedGroup>::F::random(&mut OsRng);
    pub_keys.push(<Embedwards25519 as WrappedGroup>::generator() * priv_key);
    priv_keys.push((Participant::new(1 + i).unwrap(), Zeroizing::new(priv_key)));
  }

  let mut participations = HashMap::new();
  // Shuffle the private keys so we iterate over a random subset of them
  priv_keys.shuffle(&mut OsRng);
  for (i, priv_key) in priv_keys.iter().take(usize::from(THRESHOLD)) {
    participations.insert(
      *i,
      Dkg::<Ed25519>::participate(&mut OsRng, &generators, context, THRESHOLD, &pub_keys, priv_key)
        .unwrap(),
    );
  }

  let VerifyResult::Valid(dkg) =
    Dkg::<Ed25519>::verify(&mut OsRng, &generators, context, THRESHOLD, &pub_keys, &participations)
      .unwrap()
  else {
    panic!("verify didn't return VerifyResult::Valid")
  };

  let mut group_key = None;
  let mut verification_shares = None;
  let mut all_keys = HashMap::new();
  for (i, priv_key) in priv_keys {
    let keys = dkg.keys(&priv_key).into_iter().next().unwrap();
    assert_eq!(keys.params().i(), i);
    assert_eq!(keys.params().t(), THRESHOLD);
    assert_eq!(keys.params().n(), PARTICIPANTS);
    group_key = group_key.or(Some(keys.group_key()));
    let these_verification_shares = Participant::iter()
      .take(usize::from(PARTICIPANTS))
      .map(|i| (i, keys.original_verification_share(i)))
      .collect::<HashMap<_, _>>();
    verification_shares = verification_shares.or(Some(these_verification_shares.clone()));
    assert_eq!(Some(keys.group_key()), group_key);
    assert_eq!(Some(these_verification_shares), verification_shares);

    all_keys.insert(i, keys);
  }

  // TODO: Test for all possible combinations of keys
  assert_eq!(
    <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::generator() *
      *recover_key(&all_keys.values().cloned().collect::<Vec<_>>()).unwrap(),
    group_key.unwrap()
  );
}
