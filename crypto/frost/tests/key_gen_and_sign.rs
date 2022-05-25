use std::{rc::Rc, collections::HashMap};

use rand::rngs::OsRng;

use frost::{
  Curve,
  MultisigParams, MultisigKeys,
  key_gen,
  algorithm::{Algorithm, Schnorr, SchnorrSignature},
  sign::{StateMachine, AlgorithmMachine}
};

mod common;
use common::{Secp256k1, TestHram};

const PARTICIPANTS: u16 = 8;

fn clone_without<K: Clone + std::cmp::Eq + std::hash::Hash, V: Clone>(
  map: &HashMap<K, V>,
  without: &K
) -> HashMap<K, V> {
  let mut res = map.clone();
  res.remove(without).unwrap();
  res
}

fn key_gen<C: Curve>() -> HashMap<u16, Rc<MultisigKeys<C>>> {
  let mut params = HashMap::new();
  let mut machines = HashMap::new();

  let mut commitments = HashMap::new();
  for i in 1 ..= PARTICIPANTS {
    params.insert(
      i,
      MultisigParams::new(
        ((PARTICIPANTS / 3) * 2) + 1,
        PARTICIPANTS,
        i
      ).unwrap()
    );
    machines.insert(
      i,
      key_gen::StateMachine::<C>::new(
        params[&i],
        "FROST test key_gen".to_string()
      )
    );
    commitments.insert(
      i,
      machines.get_mut(&i).unwrap().generate_coefficients(&mut OsRng).unwrap()
    );
  }

  let mut secret_shares = HashMap::new();
  for (l, machine) in machines.iter_mut() {
    secret_shares.insert(
      *l,
      machine.generate_secret_shares(&mut OsRng, clone_without(&commitments, l)).unwrap()
    );
  }

  let mut verification_shares = None;
  let mut group_key = None;
  let mut keys = HashMap::new();
  for (i, machine) in machines.iter_mut() {
    let mut our_secret_shares = HashMap::new();
    for (l, shares) in &secret_shares {
      if i == l {
        continue;
      }
      our_secret_shares.insert(*l, shares[&i].clone());
    }
    let these_keys = machine.complete(our_secret_shares).unwrap();

    // Test serialization
    assert_eq!(
      MultisigKeys::<C>::deserialize(&these_keys.serialize()).unwrap(),
      these_keys
    );

    if verification_shares.is_none() {
      verification_shares = Some(these_keys.verification_shares());
    }
    assert_eq!(verification_shares.as_ref().unwrap(), &these_keys.verification_shares());

    if group_key.is_none() {
      group_key = Some(these_keys.group_key());
    }
    assert_eq!(group_key.unwrap(), these_keys.group_key());

    keys.insert(*i, Rc::new(these_keys.clone()));
  }

  keys
}

fn sign<C: Curve, A: Algorithm<C, Signature = SchnorrSignature<C>>>(
  algorithm: A,
  keys: &HashMap<u16, Rc<MultisigKeys<C>>>
) {
  let t = keys[&1].params().t();
  let mut machines = HashMap::new();
  let mut commitments = HashMap::new();
  for i in 1 ..= t {
    machines.insert(
      i,
      AlgorithmMachine::new(
        algorithm.clone(),
        keys[&i].clone(),
        &(1 ..= t).collect::<Vec<_>>()
      ).unwrap()
    );
    commitments.insert(
      i,
      machines.get_mut(&i).unwrap().preprocess(&mut OsRng).unwrap()
    );
  }

  let mut shares = HashMap::new();
  for (i, machine) in machines.iter_mut() {
    shares.insert(
      *i,
      machine.sign(clone_without(&commitments, i), b"Hello World").unwrap()
    );
  }

  let mut signature = None;
  for (i, machine) in machines.iter_mut() {
    let sig = machine.complete(clone_without(&shares, i)).unwrap();
    if signature.is_none() {
      signature = Some(sig);
    }
    assert_eq!(sig, signature.unwrap());
  }
}

#[test]
fn key_gen_and_sign() {
  let mut keys = key_gen::<Secp256k1>();

  sign(Schnorr::<Secp256k1, TestHram>::new(), &keys);

  for i in 1 ..= u16::try_from(PARTICIPANTS).unwrap() {
    keys.insert(i, Rc::new(keys[&i].offset(Secp256k1::hash_to_F(b"offset"))));
  }
  sign(Schnorr::<Secp256k1, TestHram>::new(), &keys);
}
