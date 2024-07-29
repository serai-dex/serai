use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::OsRng;
use rand::seq::SliceRandom;

use ciphersuite::{group::ff::Field, Ciphersuite};

use crate::{
  Participant,
  evrf::*,
  tests::{THRESHOLD, PARTICIPANTS, recover_key},
};

mod proof;
use proof::{Pallas, Vesta};

#[test]
fn evrf_dkg() {
  let generators = EvrfGenerators::<Pallas>::new(THRESHOLD, PARTICIPANTS);
  let context = [0; 32];

  let mut priv_keys = vec![];
  let mut pub_keys = vec![];
  for i in 0 .. PARTICIPANTS {
    let priv_key = <Vesta as Ciphersuite>::F::random(&mut OsRng);
    pub_keys.push(<Vesta as Ciphersuite>::generator() * priv_key);
    priv_keys.push((Participant::new(1 + i).unwrap(), Zeroizing::new(priv_key)));
  }

  let mut participations = HashMap::new();
  // Shuffle the private keys so we iterate over a random subset of them
  priv_keys.shuffle(&mut OsRng);
  for (i, priv_key) in priv_keys.iter().take(usize::from(THRESHOLD)) {
    participations.insert(
      *i,
      EvrfDkg::<Pallas>::participate(
        &mut OsRng,
        &generators,
        context,
        THRESHOLD,
        &pub_keys,
        priv_key,
      )
      .unwrap()
      .into_iter()
      .next()
      .unwrap(),
    );
  }

  let VerifyResult::Valid(dkg) = EvrfDkg::<Pallas>::verify(
    &mut OsRng,
    &generators,
    context,
    THRESHOLD,
    &pub_keys,
    &participations,
  )
  .unwrap() else {
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
    verification_shares = verification_shares.or(Some(keys.verification_shares()));
    assert_eq!(Some(keys.group_key()), group_key);
    assert_eq!(Some(keys.verification_shares()), verification_shares);

    all_keys.insert(i, keys);
  }

  // TODO: Test for all possible combinations of keys
  assert_eq!(Pallas::generator() * recover_key(&all_keys), group_key.unwrap());
}
