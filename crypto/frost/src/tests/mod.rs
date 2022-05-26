use std::{rc::Rc, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use crate::{
  Curve,
  MultisigParams, MultisigKeys,
  key_gen,
  algorithm::Algorithm,
  sign::{StateMachine, AlgorithmMachine}
};

// Internal tests
mod schnorr;

// Test suites for public usage
pub mod curve;

// Literal test definitions to run during `cargo test`
#[cfg(test)]
mod literal;

pub const PARTICIPANTS: u16 = 5;
pub const THRESHOLD: u16 = ((PARTICIPANTS / 3) * 2) + 1;

pub fn clone_without<K: Clone + std::cmp::Eq + std::hash::Hash, V: Clone>(
  map: &HashMap<K, V>,
  without: &K
) -> HashMap<K, V> {
  let mut res = map.clone();
  res.remove(without).unwrap();
  res
}

pub fn key_gen<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R
) -> HashMap<u16, Rc<MultisigKeys<C>>> {
  let mut params = HashMap::new();
  let mut machines = HashMap::new();

  let mut commitments = HashMap::new();
  for i in 1 ..= PARTICIPANTS {
    params.insert(
      i,
      MultisigParams::new(
        THRESHOLD,
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
      machines.get_mut(&i).unwrap().generate_coefficients(rng).unwrap()
    );
  }

  let mut secret_shares = HashMap::new();
  for (l, machine) in machines.iter_mut() {
    secret_shares.insert(
      *l,
      // clone_without isn't necessary, as this machine's own data will be inserted without
      // conflict, yet using it ensures the machine's own data is actually inserted as expected
      machine.generate_secret_shares(rng, clone_without(&commitments, l)).unwrap()
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

    // Verify the verification_shares are agreed upon
    if verification_shares.is_none() {
      verification_shares = Some(these_keys.verification_shares());
    }
    assert_eq!(verification_shares.as_ref().unwrap(), &these_keys.verification_shares());

    // Verify the group keys are agreed upon
    if group_key.is_none() {
      group_key = Some(these_keys.group_key());
    }
    assert_eq!(group_key.unwrap(), these_keys.group_key());

    keys.insert(*i, Rc::new(these_keys));
  }

  keys
}

pub fn algorithm_machines<R: RngCore, C: Curve, A: Algorithm<C>>(
  rng: &mut R,
  algorithm: A,
  keys: &HashMap<u16, Rc<MultisigKeys<C>>>,
) -> HashMap<u16, AlgorithmMachine<C, A>> {
  let mut included = vec![];
  while included.len() < usize::from(keys[&1].params().t()) {
    let n = u16::try_from((rng.next_u64() % u64::try_from(keys.len()).unwrap()) + 1).unwrap();
    if included.contains(&n) {
      continue;
    }
    included.push(n);
  }

  keys.iter().filter_map(
    |(i, keys)| if included.contains(&i) {
      Some((
        *i,
        AlgorithmMachine::new(
          algorithm.clone(),
          keys.clone(),
          &included.clone()
        ).unwrap()
      ))
    } else {
      None
    }
  ).collect()
}

pub fn sign<R: RngCore + CryptoRng, M: StateMachine>(
  rng: &mut R,
  mut machines: HashMap<u16, M>,
  msg: &[u8]
) -> M::Signature {
  let mut commitments = HashMap::new();
  for (i, machine) in machines.iter_mut() {
    commitments.insert(*i, machine.preprocess(rng).unwrap());
  }

  let mut shares = HashMap::new();
  for (i, machine) in machines.iter_mut() {
    shares.insert(
      *i,
      machine.sign(clone_without(&commitments, i), msg).unwrap()
    );
  }

  let mut signature = None;
  for (i, machine) in machines.iter_mut() {
    let sig = machine.complete(clone_without(&shares, i)).unwrap();
    if signature.is_none() {
      signature = Some(sig.clone());
    }
    assert_eq!(&sig, signature.as_ref().unwrap());
  }
  signature.unwrap()
}
