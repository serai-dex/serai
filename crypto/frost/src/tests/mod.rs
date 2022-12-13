use std::collections::HashMap;

use rand::{RngCore, CryptoRng};

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
        Some((*i, AlgorithmMachine::new(algorithm.clone(), keys.clone()).unwrap()))
      } else {
        None
      }
    })
    .collect()
}

fn sign_internal<
  R: RngCore + CryptoRng,
  M: PreprocessMachine,
  F: FnMut(&mut R, &mut HashMap<u16, M::SignMachine>),
>(
  rng: &mut R,
  mut machines: HashMap<u16, M>,
  mut cache: F,
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

  cache(rng, &mut machines);

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

/// Execute the signing protocol, without caching any machines. This isn't as comprehensive at
/// testing as sign, and accordingly isn't preferred, yet is usable for machines not supporting
/// caching.
pub fn sign_without_caching<R: RngCore + CryptoRng, M: PreprocessMachine>(
  rng: &mut R,
  machines: HashMap<u16, M>,
  msg: &[u8],
) -> M::Signature {
  sign_internal(rng, machines, |_, _| {}, msg)
}

/// Execute the signing protocol, randomly caching various machines to ensure they can cache
/// successfully.
pub fn sign<R: RngCore + CryptoRng, M: PreprocessMachine>(
  rng: &mut R,
  params: <M::SignMachine as SignMachine<M::Signature>>::Params,
  mut keys: HashMap<u16, <M::SignMachine as SignMachine<M::Signature>>::Keys>,
  machines: HashMap<u16, M>,
  msg: &[u8],
) -> M::Signature {
  sign_internal(
    rng,
    machines,
    |rng, machines| {
      // Cache and rebuild half of the machines
      let mut included = machines.keys().into_iter().cloned().collect::<Vec<_>>();
      for i in included.drain(..) {
        if (rng.next_u64() % 2) == 0 {
          let cache = machines.remove(&i).unwrap().cache();
          machines.insert(
            i,
            M::SignMachine::from_cache(params.clone(), keys.remove(&i).unwrap(), cache).unwrap(),
          );
        }
      }
    },
    msg,
  )
}
