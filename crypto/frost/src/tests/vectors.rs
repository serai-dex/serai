use core::ops::Deref;

use std::collections::HashMap;
#[cfg(test)]
use std::str::FromStr;

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use group::{ff::PrimeField, GroupEncoding};

use dkg::tests::key_gen;

use crate::{
  curve::Curve,
  ThresholdCore, ThresholdKeys, FrostError,
  algorithm::{Schnorr, Hram},
  sign::{
    Nonce, GeneratorCommitments, NonceCommitments, Commitments, Writable, Preprocess, SignMachine,
    SignatureMachine, AlgorithmMachine,
  },
  tests::{clone_without, recover_key, algorithm_machines, commit_and_shares, sign},
};

pub struct Vectors {
  pub threshold: u16,

  pub group_secret: String,
  pub group_key: String,
  pub shares: Vec<String>,

  pub msg: String,
  pub included: Vec<u16>,
  pub nonces: Vec<[String; 2]>,

  pub sig_shares: Vec<String>,

  pub sig: String,
}

#[cfg(test)]
impl From<serde_json::Value> for Vectors {
  fn from(value: serde_json::Value) -> Vectors {
    let to_str = |value: &serde_json::Value| value.as_str().unwrap().to_string();
    Vectors {
      threshold: u16::from_str(value["config"]["NUM_PARTICIPANTS"].as_str().unwrap()).unwrap(),

      group_secret: to_str(&value["inputs"]["group_secret_key"]),
      group_key: to_str(&value["inputs"]["group_public_key"]),
      shares: value["inputs"]["participants"]
        .as_object()
        .unwrap()
        .values()
        .map(|share| to_str(&share["participant_share"]))
        .collect(),

      msg: to_str(&value["inputs"]["message"]),
      included: to_str(&value["round_one_outputs"]["participant_list"])
        .split(',')
        .map(u16::from_str)
        .collect::<Result<_, _>>()
        .unwrap(),
      nonces: value["round_one_outputs"]["participants"]
        .as_object()
        .unwrap()
        .values()
        .map(|value| [to_str(&value["hiding_nonce"]), to_str(&value["binding_nonce"])])
        .collect(),

      sig_shares: value["round_two_outputs"]["participants"]
        .as_object()
        .unwrap()
        .values()
        .map(|value| to_str(&value["sig_share"]))
        .collect(),

      sig: to_str(&value["final_output"]["sig"]),
    }
  }
}

// Load these vectors into ThresholdKeys using a custom serialization it'll deserialize
fn vectors_to_multisig_keys<C: Curve>(vectors: &Vectors) -> HashMap<u16, ThresholdKeys<C>> {
  let shares = vectors
    .shares
    .iter()
    .map(|secret| C::read_F::<&[u8]>(&mut hex::decode(secret).unwrap().as_ref()).unwrap())
    .collect::<Vec<_>>();
  let verification_shares = shares.iter().map(|secret| C::generator() * secret).collect::<Vec<_>>();

  let mut keys = HashMap::new();
  for i in 1 ..= u16::try_from(shares.len()).unwrap() {
    // Manually re-implement the serialization for ThresholdCore to import this data
    let mut serialized = vec![];
    serialized.extend(u32::try_from(C::ID.len()).unwrap().to_be_bytes());
    serialized.extend(C::ID);
    serialized.extend(vectors.threshold.to_be_bytes());
    serialized.extend(u16::try_from(shares.len()).unwrap().to_be_bytes());
    serialized.extend(i.to_be_bytes());
    serialized.extend(shares[usize::from(i) - 1].to_repr().as_ref());
    for share in &verification_shares {
      serialized.extend(share.to_bytes().as_ref());
    }

    let these_keys = ThresholdCore::<C>::read::<&[u8]>(&mut serialized.as_ref()).unwrap();
    assert_eq!(these_keys.params().t(), vectors.threshold);
    assert_eq!(usize::from(these_keys.params().n()), shares.len());
    assert_eq!(these_keys.params().i(), i);
    assert_eq!(these_keys.secret_share().deref(), &shares[usize::from(i - 1)]);
    assert_eq!(hex::encode(these_keys.group_key().to_bytes().as_ref()), vectors.group_key);
    keys.insert(i, ThresholdKeys::new(these_keys));
  }

  keys
}

pub fn test_with_vectors<R: RngCore + CryptoRng, C: Curve, H: Hram<C>>(
  rng: &mut R,
  vectors: Vectors,
) {
  // Test a basic Schnorr signature
  {
    let keys = key_gen(&mut *rng);
    let machines = algorithm_machines(&mut *rng, Schnorr::<C, H>::new(), &keys);
    const MSG: &[u8] = b"Hello, World!";
    let sig = sign(&mut *rng, Schnorr::<C, H>::new(), keys.clone(), machines, MSG);
    assert!(sig.verify(keys[&1].group_key(), H::hram(&sig.R, &keys[&1].group_key(), MSG)));
  }

  // Test blame on an invalid Schnorr signature share
  {
    let keys = key_gen(&mut *rng);
    let machines = algorithm_machines(&mut *rng, Schnorr::<C, H>::new(), &keys);
    const MSG: &[u8] = b"Hello, World!";

    let (mut machines, mut shares) = commit_and_shares(&mut *rng, machines, |_, _| {}, MSG);
    let faulty = *shares.keys().next().unwrap();
    shares.get_mut(&faulty).unwrap().invalidate();

    for (i, machine) in machines.drain() {
      if i == faulty {
        continue;
      }
      assert_eq!(
        machine.complete(clone_without(&shares, &i)).err(),
        Some(FrostError::InvalidShare(faulty))
      );
    }
  }

  // Test against the vectors
  let keys = vectors_to_multisig_keys::<C>(&vectors);
  let group_key =
    <C as Curve>::read_G::<&[u8]>(&mut hex::decode(&vectors.group_key).unwrap().as_ref()).unwrap();
  let secret =
    C::read_F::<&[u8]>(&mut hex::decode(&vectors.group_secret).unwrap().as_ref()).unwrap();
  assert_eq!(C::generator() * secret, group_key);
  assert_eq!(recover_key(&keys), secret);

  let mut machines = vec![];
  for i in &vectors.included {
    machines.push((i, AlgorithmMachine::new(Schnorr::<C, H>::new(), keys[i].clone()).unwrap()));
  }

  let mut commitments = HashMap::new();
  let mut c = 0;
  let mut machines = machines
    .drain(..)
    .map(|(i, machine)| {
      let nonce = |i| {
        Zeroizing::new(
          C::read_F::<&[u8]>(&mut hex::decode(&vectors.nonces[c][i]).unwrap().as_ref()).unwrap(),
        )
      };
      let nonces = [nonce(0), nonce(1)];
      c += 1;
      let these_commitments =
        [C::generator() * nonces[0].deref(), C::generator() * nonces[1].deref()];
      let machine = machine.unsafe_override_preprocess(
        vec![Nonce(nonces)],
        Preprocess {
          commitments: Commitments {
            nonces: vec![NonceCommitments {
              generators: vec![GeneratorCommitments(these_commitments)],
            }],
            dleq: None,
          },
          addendum: (),
        },
      );

      commitments.insert(
        *i,
        machine
          .read_preprocess::<&[u8]>(
            &mut [
              these_commitments[0].to_bytes().as_ref(),
              these_commitments[1].to_bytes().as_ref(),
            ]
            .concat()
            .as_ref(),
          )
          .unwrap(),
      );
      (i, machine)
    })
    .collect::<Vec<_>>();

  let mut shares = HashMap::new();
  c = 0;
  let mut machines = machines
    .drain(..)
    .map(|(i, machine)| {
      let (machine, share) =
        machine.sign(clone_without(&commitments, i), &hex::decode(&vectors.msg).unwrap()).unwrap();

      let share = {
        let mut buf = vec![];
        share.write(&mut buf).unwrap();
        buf
      };
      assert_eq!(share, hex::decode(&vectors.sig_shares[c]).unwrap());
      c += 1;

      shares.insert(*i, machine.read_share::<&[u8]>(&mut share.as_ref()).unwrap());
      (i, machine)
    })
    .collect::<HashMap<_, _>>();

  for (i, machine) in machines.drain() {
    let sig = machine.complete(clone_without(&shares, i)).unwrap();
    let mut serialized = sig.R.to_bytes().as_ref().to_vec();
    serialized.extend(sig.s.to_repr().as_ref());
    assert_eq!(hex::encode(serialized), vectors.sig);
  }
}
