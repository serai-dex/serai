use std::{io::Cursor, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use group::ff::Field;

use crate::{
  Curve, FrostParams, FrostCore, FrostKeys, lagrange,
  key_gen::KeyGenMachine,
  algorithm::Algorithm,
  sign::{PreprocessMachine, SignMachine, SignatureMachine, AlgorithmMachine},
};

/// Curve tests.
pub mod curve;
/// Schnorr signature tests.
pub mod schnorr;
/// Promotion tests.
pub mod promote;
/// Vectorized test suite to ensure consistency.
pub mod vectors;

// Literal test definitions to run during `cargo test`
#[cfg(test)]
mod literal;

/// Constant amount of participants to use when testing.
pub const PARTICIPANTS: u16 = 5;
/// Constant threshold of participants to use when signing.
pub const THRESHOLD: u16 = ((PARTICIPANTS / 3) * 2) + 1;

/// Clone a map without a specific value.
pub fn clone_without<K: Clone + std::cmp::Eq + std::hash::Hash, V: Clone>(
  map: &HashMap<K, V>,
  without: &K,
) -> HashMap<K, V> {
  let mut res = map.clone();
  res.remove(without).unwrap();
  res
}

/// Generate FROST keys (as FrostCore objects) for tests.
pub fn core_gen<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) -> HashMap<u16, FrostCore<C>> {
  let mut machines = HashMap::new();
  let mut commitments = HashMap::new();
  for i in 1 ..= PARTICIPANTS {
    let machine = KeyGenMachine::<C>::new(
      FrostParams::new(THRESHOLD, PARTICIPANTS, i).unwrap(),
      "FROST Test key_gen".to_string(),
    );
    let (machine, these_commitments) = machine.generate_coefficients(rng);
    machines.insert(i, machine);
    commitments.insert(i, Cursor::new(these_commitments));
  }

  let mut secret_shares = HashMap::new();
  let mut machines = machines
    .drain()
    .map(|(l, machine)| {
      let (machine, shares) =
        machine.generate_secret_shares(rng, clone_without(&commitments, &l)).unwrap();
      secret_shares.insert(l, shares);
      (l, machine)
    })
    .collect::<HashMap<_, _>>();

  let mut verification_shares = None;
  let mut group_key = None;
  machines
    .drain()
    .map(|(i, machine)| {
      let mut our_secret_shares = HashMap::new();
      for (l, shares) in &secret_shares {
        if i == *l {
          continue;
        }
        our_secret_shares.insert(*l, Cursor::new(shares[&i].clone()));
      }
      let these_keys = machine.complete(rng, our_secret_shares).unwrap();

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

      (i, these_keys)
    })
    .collect::<HashMap<_, _>>()
}

/// Generate FROST keys for tests.
pub fn key_gen<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) -> HashMap<u16, FrostKeys<C>> {
  core_gen(rng).drain().map(|(i, core)| (i, FrostKeys::new(core))).collect()
}

/// Recover the secret from a collection of keys.
pub fn recover<C: Curve>(keys: &HashMap<u16, FrostKeys<C>>) -> C::F {
  let first = keys.values().next().expect("no keys provided");
  assert!(keys.len() >= first.params().t().into(), "not enough keys provided");
  let included = keys.keys().cloned().collect::<Vec<_>>();

  let group_private = keys.iter().fold(C::F::zero(), |accum, (i, keys)| {
    accum + (keys.secret_share() * lagrange::<C::F>(*i, &included))
  });
  assert_eq!(C::generator() * group_private, first.group_key(), "failed to recover keys");
  group_private
}

/// Spawn algorithm machines for a random selection of signers, each executing the given algorithm.
pub fn algorithm_machines<R: RngCore, C: Curve, A: Algorithm<C>>(
  rng: &mut R,
  algorithm: A,
  keys: &HashMap<u16, FrostKeys<C>>,
) -> HashMap<u16, AlgorithmMachine<C, A>> {
  let mut included = vec![];
  while included.len() < usize::from(keys[&1].params().t()) {
    let n = u16::try_from((rng.next_u64() % u64::try_from(keys.len()).unwrap()) + 1).unwrap();
    if included.contains(&n) {
      continue;
    }
    included.push(n);
  }

  keys
    .iter()
    .filter_map(|(i, keys)| {
      if included.contains(i) {
        Some((
          *i,
          AlgorithmMachine::new(algorithm.clone(), keys.clone(), &included.clone()).unwrap(),
        ))
      } else {
        None
      }
    })
    .collect()
}

/// Execute the signing protocol.
pub fn sign<R: RngCore + CryptoRng, M: PreprocessMachine>(
  rng: &mut R,
  mut machines: HashMap<u16, M>,
  msg: &[u8],
) -> M::Signature {
  let mut commitments = HashMap::new();
  let mut machines = machines
    .drain()
    .map(|(i, machine)| {
      let (machine, preprocess) = machine.preprocess(rng);
      commitments.insert(i, Cursor::new(preprocess));
      (i, machine)
    })
    .collect::<HashMap<_, _>>();

  let mut shares = HashMap::new();
  let mut machines = machines
    .drain()
    .map(|(i, machine)| {
      let (machine, share) = machine.sign(clone_without(&commitments, &i), msg).unwrap();
      shares.insert(i, Cursor::new(share));
      (i, machine)
    })
    .collect::<HashMap<_, _>>();

  let mut signature = None;
  for (i, machine) in machines.drain() {
    let sig = machine.complete(clone_without(&shares, &i)).unwrap();
    if signature.is_none() {
      signature = Some(sig.clone());
    }
    assert_eq!(&sig, signature.as_ref().unwrap());
  }
  signature.unwrap()
}
