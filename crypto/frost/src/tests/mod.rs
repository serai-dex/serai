use std::collections::HashMap;

use rand_core::{RngCore, CryptoRng};

pub use dkg::tests::{key_gen, recover_key};

use crate::{
  Curve, ThresholdKeys,
  algorithm::Algorithm,
  sign::{Writable, PreprocessMachine, SignMachine, SignatureMachine, AlgorithmMachine},
};

/// Curve tests.
pub mod curve;
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

/// Spawn algorithm machines for a random selection of signers, each executing the given algorithm.
pub fn algorithm_machines<R: RngCore, C: Curve, A: Algorithm<C>>(
  rng: &mut R,
  algorithm: A,
  keys: &HashMap<u16, ThresholdKeys<C>>,
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
      commitments.insert(i, {
        let mut buf = vec![];
        preprocess.write(&mut buf).unwrap();
        machine.read_preprocess::<&[u8]>(&mut buf.as_ref()).unwrap()
      });
      (i, machine)
    })
    .collect::<HashMap<_, _>>();

  let mut shares = HashMap::new();
  let mut machines = machines
    .drain()
    .map(|(i, machine)| {
      let (machine, share) = machine.sign(clone_without(&commitments, &i), msg).unwrap();
      shares.insert(i, {
        let mut buf = vec![];
        share.write(&mut buf).unwrap();
        machine.read_share::<&[u8]>(&mut buf.as_ref()).unwrap()
      });
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
