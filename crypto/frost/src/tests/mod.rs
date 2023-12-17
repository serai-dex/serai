use std::collections::HashMap;

use rand_core::{RngCore, CryptoRng};

pub use dkg::tests::{key_gen, musig_key_gen, recover_key};

use crate::{
  Curve, Participant, ThresholdKeys, FrostError,
  algorithm::{Algorithm, Hram, IetfSchnorr},
  sign::{Writable, PreprocessMachine, SignMachine, SignatureMachine, AlgorithmMachine},
};

/// Tests for the nonce handling code.
pub mod nonces;
use nonces::{test_multi_nonce, test_invalid_commitment, test_invalid_dleq_proof};

/// Vectorized test suite to ensure consistency.
pub mod vectors;

// Literal test definitions to run during `cargo test`
#[cfg(test)]
mod literal;

/// Constant amount of participants to use when testing.
pub const PARTICIPANTS: u16 = 5;
/// Constant threshold of participants to use when signing.
pub const THRESHOLD: u16 = ((PARTICIPANTS * 2) / 3) + 1;

/// Clone a map without a specific value.
pub fn clone_without<K: Clone + core::cmp::Eq + core::hash::Hash, V: Clone>(
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
  keys: &HashMap<Participant, ThresholdKeys<C>>,
) -> HashMap<Participant, AlgorithmMachine<C, A>> {
  let mut included = vec![];
  while included.len() < usize::from(keys[&Participant::new(1).unwrap()].params().t()) {
    let n = Participant::new(
      u16::try_from((rng.next_u64() % u64::try_from(keys.len()).unwrap()) + 1).unwrap(),
    )
    .unwrap();
    if included.contains(&n) {
      continue;
    }
    included.push(n);
  }

  keys
    .iter()
    .filter_map(|(i, keys)| {
      if included.contains(i) {
        Some((*i, AlgorithmMachine::new(algorithm.clone(), keys.clone())))
      } else {
        None
      }
    })
    .collect()
}

// Run the preprocess step
pub(crate) fn preprocess<
  R: RngCore + CryptoRng,
  M: PreprocessMachine,
  F: FnMut(&mut R, &mut HashMap<Participant, M::SignMachine>),
>(
  rng: &mut R,
  mut machines: HashMap<Participant, M>,
  mut cache: F,
) -> (HashMap<Participant, M::SignMachine>, HashMap<Participant, M::Preprocess>) {
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

  (machines, commitments)
}

// Run the preprocess and generate signature shares
#[allow(clippy::type_complexity)]
pub(crate) fn preprocess_and_shares<
  R: RngCore + CryptoRng,
  M: PreprocessMachine,
  F: FnMut(&mut R, &mut HashMap<Participant, M::SignMachine>),
>(
  rng: &mut R,
  machines: HashMap<Participant, M>,
  cache: F,
  msg: &[u8],
) -> (
  HashMap<Participant, <M::SignMachine as SignMachine<M::Signature>>::SignatureMachine>,
  HashMap<Participant, <M::SignMachine as SignMachine<M::Signature>>::SignatureShare>,
) {
  let (mut machines, commitments) = preprocess(rng, machines, cache);

  let mut shares = HashMap::new();
  let machines = machines
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

  (machines, shares)
}

fn sign_internal<
  R: RngCore + CryptoRng,
  M: PreprocessMachine,
  F: FnMut(&mut R, &mut HashMap<Participant, M::SignMachine>),
>(
  rng: &mut R,
  machines: HashMap<Participant, M>,
  cache: F,
  msg: &[u8],
) -> M::Signature {
  let (mut machines, shares) = preprocess_and_shares(rng, machines, cache, msg);

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
  machines: HashMap<Participant, M>,
  msg: &[u8],
) -> M::Signature {
  sign_internal(rng, machines, |_, _| {}, msg)
}

/// Execute the signing protocol, randomly caching various machines to ensure they can cache
/// successfully.
pub fn sign<R: RngCore + CryptoRng, M: PreprocessMachine>(
  rng: &mut R,
  params: <M::SignMachine as SignMachine<M::Signature>>::Params,
  mut keys: HashMap<Participant, <M::SignMachine as SignMachine<M::Signature>>::Keys>,
  machines: HashMap<Participant, M>,
  msg: &[u8],
) -> M::Signature {
  sign_internal(
    rng,
    machines,
    |rng, machines| {
      // Cache and rebuild half of the machines
      let included = machines.keys().copied().collect::<Vec<_>>();
      for i in included {
        if (rng.next_u64() % 2) == 0 {
          let cache = machines.remove(&i).unwrap().cache();
          machines.insert(
            i,
            M::SignMachine::from_cache(params.clone(), keys.remove(&i).unwrap(), cache).0,
          );
        }
      }
    },
    msg,
  )
}

/// Test a basic Schnorr signature with the provided keys.
pub fn test_schnorr_with_keys<R: RngCore + CryptoRng, C: Curve, H: Hram<C>>(
  rng: &mut R,
  keys: HashMap<Participant, ThresholdKeys<C>>,
) {
  const MSG: &[u8] = b"Hello, World!";

  let machines = algorithm_machines(&mut *rng, IetfSchnorr::<C, H>::ietf(), &keys);
  let sig = sign(&mut *rng, IetfSchnorr::<C, H>::ietf(), keys.clone(), machines, MSG);
  let group_key = keys[&Participant::new(1).unwrap()].group_key();
  assert!(sig.verify(group_key, H::hram(&sig.R, &group_key, MSG)));
}

/// Test a basic Schnorr signature.
pub fn test_schnorr<R: RngCore + CryptoRng, C: Curve, H: Hram<C>>(rng: &mut R) {
  let keys = key_gen(&mut *rng);
  test_schnorr_with_keys::<_, _, H>(&mut *rng, keys)
}

/// Test a basic Schnorr signature, yet with MuSig.
pub fn test_musig_schnorr<R: RngCore + CryptoRng, C: Curve, H: Hram<C>>(rng: &mut R) {
  let keys = musig_key_gen(&mut *rng);
  test_schnorr_with_keys::<_, _, H>(&mut *rng, keys)
}

/// Test an offset Schnorr signature.
pub fn test_offset_schnorr<R: RngCore + CryptoRng, C: Curve, H: Hram<C>>(rng: &mut R) {
  const MSG: &[u8] = b"Hello, World!";

  let mut keys = key_gen(&mut *rng);
  let group_key = keys[&Participant::new(1).unwrap()].group_key();

  let offset = C::F::from(5);
  let offset_key = group_key + (C::generator() * offset);
  for keys in keys.values_mut() {
    *keys = keys.offset(offset);
    assert_eq!(keys.group_key(), offset_key);
  }

  let machines = algorithm_machines(&mut *rng, IetfSchnorr::<C, H>::ietf(), &keys);
  let sig = sign(&mut *rng, IetfSchnorr::<C, H>::ietf(), keys.clone(), machines, MSG);
  let group_key = keys[&Participant::new(1).unwrap()].group_key();
  assert!(sig.verify(offset_key, H::hram(&sig.R, &group_key, MSG)));
}

/// Test blame for an invalid Schnorr signature share.
pub fn test_schnorr_blame<R: RngCore + CryptoRng, C: Curve, H: Hram<C>>(rng: &mut R) {
  const MSG: &[u8] = b"Hello, World!";

  let keys = key_gen(&mut *rng);
  let machines = algorithm_machines(&mut *rng, IetfSchnorr::<C, H>::ietf(), &keys);

  let (mut machines, shares) = preprocess_and_shares(&mut *rng, machines, |_, _| {}, MSG);

  for (i, machine) in machines.drain() {
    let mut shares = clone_without(&shares, &i);

    // Select a random participant to give an invalid share
    let participants = shares.keys().collect::<Vec<_>>();
    let faulty = *participants
      [usize::try_from(rng.next_u64() % u64::try_from(participants.len()).unwrap()).unwrap()];
    shares.get_mut(&faulty).unwrap().invalidate();

    assert_eq!(machine.complete(shares).err(), Some(FrostError::InvalidShare(faulty)));
  }
}

/// Run a variety of tests against a ciphersuite.
pub fn test_ciphersuite<R: RngCore + CryptoRng, C: Curve, H: Hram<C>>(rng: &mut R) {
  test_schnorr::<R, C, H>(rng);
  test_musig_schnorr::<R, C, H>(rng);
  test_offset_schnorr::<R, C, H>(rng);
  test_schnorr_blame::<R, C, H>(rng);

  test_multi_nonce::<R, C>(rng);
  test_invalid_commitment::<R, C>(rng);
  test_invalid_dleq_proof::<R, C>(rng);
}
