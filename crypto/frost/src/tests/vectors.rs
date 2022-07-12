use std::{sync::Arc, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use group::{ff::PrimeField, GroupEncoding};

use crate::{
  curve::{Curve, F_from_slice, G_from_slice}, FrostKeys,
  algorithm::{Schnorr, Hram},
  sign::{PreprocessPackage, SignMachine, SignatureMachine, AlgorithmMachine},
  tests::{curve::test_curve, schnorr::test_schnorr, recover}
};

pub struct Vectors {
  pub threshold: u16,
  pub shares: &'static [&'static str],
  pub group_secret: &'static str,
  pub group_key: &'static str,

  pub msg: &'static str,
  pub included: &'static [u16],
  pub nonces: &'static [[&'static str; 2]],
  pub sig_shares: &'static [&'static str],
  pub sig: String
}

// Load these vectors into FrostKeys using a custom serialization it'll deserialize
fn vectors_to_multisig_keys<C: Curve>(vectors: &Vectors) -> HashMap<u16, FrostKeys<C>> {
  let shares = vectors.shares.iter().map(
    |secret| F_from_slice::<C::F>(&hex::decode(secret).unwrap()).unwrap()
  ).collect::<Vec<_>>();
  let verification_shares = shares.iter().map(
    |secret| C::GENERATOR * secret
  ).collect::<Vec<_>>();

  let mut keys = HashMap::new();
  for i in 1 ..= u16::try_from(shares.len()).unwrap() {
    let mut serialized = vec![];
    serialized.extend(u64::try_from(C::ID.len()).unwrap().to_be_bytes());
    serialized.extend(C::ID);
    serialized.extend(vectors.threshold.to_be_bytes());
    serialized.extend(u16::try_from(shares.len()).unwrap().to_be_bytes());
    serialized.extend(i.to_be_bytes());
    serialized.extend(shares[usize::from(i) - 1].to_repr().as_ref());
    serialized.extend(&hex::decode(vectors.group_key).unwrap());
    for share in &verification_shares {
      serialized.extend(share.to_bytes().as_ref());
    }

    let these_keys = FrostKeys::<C>::deserialize(&serialized).unwrap();
    assert_eq!(these_keys.params().t(), vectors.threshold);
    assert_eq!(usize::from(these_keys.params().n()), shares.len());
    assert_eq!(these_keys.params().i(), i);
    assert_eq!(these_keys.secret_share(), shares[usize::from(i - 1)]);
    assert_eq!(&hex::encode(these_keys.group_key().to_bytes().as_ref()), vectors.group_key);
    keys.insert(i, these_keys);
  }

  keys
}

pub fn test_with_vectors<
  R: RngCore + CryptoRng,
  C: Curve,
  H: Hram<C>
>(rng: &mut R, vectors: Vectors) {
  // Do basic tests before trying the vectors
  test_curve::<_, C>(&mut *rng);
  test_schnorr::<_, C>(rng);

  // Test against the vectors
  let keys = vectors_to_multisig_keys::<C>(&vectors);
  let group_key = G_from_slice::<C::G>(&hex::decode(vectors.group_key).unwrap()).unwrap();
  assert_eq!(
    C::GENERATOR * F_from_slice::<C::F>(&hex::decode(vectors.group_secret).unwrap()).unwrap(),
    group_key
  );
  assert_eq!(
    recover(&keys),
    F_from_slice::<C::F>(&hex::decode(vectors.group_secret).unwrap()).unwrap()
  );

  let mut machines = vec![];
  for i in vectors.included {
    machines.push((
      *i,
      AlgorithmMachine::new(
        Schnorr::<C, H>::new(),
        Arc::new(keys[i].clone()),
        vectors.included.clone()
      ).unwrap()
    ));
  }

  let mut commitments = HashMap::new();
  let mut c = 0;
  let mut machines = machines.drain(..).map(|(i, machine)| {
    let nonces = [
      F_from_slice::<C::F>(&hex::decode(vectors.nonces[c][0]).unwrap()).unwrap(),
      F_from_slice::<C::F>(&hex::decode(vectors.nonces[c][1]).unwrap()).unwrap()
    ];
    c += 1;

    let mut serialized = (C::GENERATOR * nonces[0]).to_bytes().as_ref().to_vec();
    serialized.extend((C::GENERATOR * nonces[1]).to_bytes().as_ref());

    let (machine, serialized) = machine.unsafe_override_preprocess(
      PreprocessPackage { nonces: vec![nonces], serialized: serialized.clone() }
    );

    commitments.insert(i, serialized);
    (i, machine)
  }).collect::<Vec<_>>();

  let mut shares = HashMap::new();
  c = 0;
  let mut machines = machines.drain(..).map(|(i, machine)| {
    let (machine, share) = machine.sign(
      commitments.clone(),
      &hex::decode(vectors.msg).unwrap()
    ).unwrap();

    assert_eq!(share, hex::decode(vectors.sig_shares[c]).unwrap());
    c += 1;

    shares.insert(i, share);
    (i, machine)
  }).collect::<HashMap<_, _>>();

  for (_, machine) in machines.drain() {
    let sig = machine.complete(shares.clone()).unwrap();
    let mut serialized = sig.R.to_bytes().as_ref().to_vec();
    serialized.extend(sig.s.to_repr().as_ref());
    assert_eq!(hex::encode(serialized), vectors.sig);
  }
}
