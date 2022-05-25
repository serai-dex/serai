#![cfg(feature = "multisig")]

use std::collections::HashMap;

use rand::rngs::OsRng;

use ff::Field;
use dalek_ff_group::{ED25519_BASEPOINT_TABLE, Scalar};

pub use frost::{
  FrostError, MultisigParams, MultisigKeys,
  lagrange, key_gen, algorithm::Algorithm, sign
};

use monero_serai::frost::Ed25519;

pub const THRESHOLD: u16 = 3;
pub const PARTICIPANTS: u16 = 5;

fn clone_without<K: Clone + std::cmp::Eq + std::hash::Hash, V: Clone>(
  map: &HashMap<K, V>,
  without: &K
) -> HashMap<K, V> {
  let mut res = map.clone();
  res.remove(without).unwrap();
  res
}

pub fn generate_keys() -> (HashMap<u16, MultisigKeys<Ed25519>>, Scalar) {
  let mut params = HashMap::new();
  let mut machines = HashMap::new();
  let mut commitments = HashMap::new();
  for i in 1 ..= PARTICIPANTS {
    params.insert(
      i,
      MultisigParams::new(THRESHOLD, PARTICIPANTS, i).unwrap()
    );
    machines.insert(
      i,
      key_gen::StateMachine::<Ed25519>::new(
        params[&i],
        "monero-sign-rs test suite".to_string()
      )
    );
    commitments.insert(i, machines.get_mut(&i).unwrap().generate_coefficients(&mut OsRng).unwrap());
  }

  let mut secret_shares = HashMap::new();
  for (i, machine) in machines.iter_mut() {
    secret_shares.insert(
      *i,
      machine.generate_secret_shares(&mut OsRng, clone_without(&commitments, i)).unwrap()
    );
  }

  let mut keys = HashMap::new();
  for (i, machine) in machines.iter_mut() {
    let mut our_secret_shares = HashMap::new();
    for (l, shares) in &secret_shares {
      if i == l {
        continue;
      }
      our_secret_shares.insert(*l, shares[&i].clone());
    }
    keys.insert(*i, machine.complete(our_secret_shares).unwrap().clone());
  }

  let mut group_private = Scalar::zero();
  for i in 1 ..= THRESHOLD {
    group_private += keys[&i].secret_share() * lagrange::<Scalar>(i, &(1 ..= THRESHOLD).collect::<Vec<_>>());
  }
  assert_eq!(&ED25519_BASEPOINT_TABLE * group_private, keys[&1].group_key());

  (keys, group_private)
}

pub fn sign<S, M: sign::StateMachine<Signature = S>>(machines: &mut HashMap<u16, M>, msg: &[u8]) -> Vec<S> {
  assert!(machines.len() >= THRESHOLD.into());

  let mut commitments = HashMap::new();
  for (i, machine) in machines.iter_mut() {
    commitments.insert(*i, machine.preprocess(&mut OsRng).unwrap());
  }

  let mut shares = HashMap::new();
  for (i, machine) in machines.iter_mut() {
    shares.insert(*i, machine.sign(clone_without(&commitments, i), msg).unwrap());
  }

  let mut res = vec![];
  for (i, machine) in machines.iter_mut() {
    res.push(machine.complete(clone_without(&shares, i)).unwrap())
  }
  res
}
