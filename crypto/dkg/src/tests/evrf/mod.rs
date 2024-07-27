use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::OsRng;
use rand::seq::SliceRandom;

use ciphersuite::{group::ff::Field, Ciphersuite};

use crate::{
  Participant, ThresholdKeys,
  evrf::*,
  tests::{THRESHOLD, PARTICIPANTS},
};

mod proof;
use proof::{Pallas, Vesta};

#[test]
fn evrf_dkg() {
  let generators = EvrfDkg::<Pallas>::generators(THRESHOLD, PARTICIPANTS);

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
        [0; 32],
        THRESHOLD,
        &pub_keys,
        priv_key,
      )
      .unwrap(),
    );
  }

  let dkg = EvrfDkg::<Pallas>::verify(
    &mut OsRng,
    &generators,
    [0; 32],
    THRESHOLD,
    &pub_keys,
    &participations,
  )
  .unwrap();

  for (i, priv_key) in priv_keys {
    let keys = ThresholdKeys::from(dkg.keys(&priv_key).unwrap());
    assert_eq!(keys.params().i(), i);
    assert_eq!(keys.params().t(), THRESHOLD);
    assert_eq!(keys.params().n(), PARTICIPANTS);
  }
}
