use std::{io::Cursor, collections::HashMap};
#[cfg(test)]
use std::str::FromStr;

use rand_core::{RngCore, CryptoRng};

use group::{ff::PrimeField, GroupEncoding};

use crate::{
  curve::Curve,
  FrostCore, FrostKeys,
  algorithm::{Schnorr, Hram},
  sign::{PreprocessPackage, SignMachine, SignatureMachine, AlgorithmMachine},
  tests::{
    clone_without, curve::test_curve, schnorr::test_schnorr, promote::test_promotion, recover,
  },
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
        .split(",")
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

// Load these vectors into FrostKeys using a custom serialization it'll deserialize
fn vectors_to_multisig_keys<C: Curve>(vectors: &Vectors) -> HashMap<u16, FrostKeys<C>> {
  let shares = vectors
    .shares
    .iter()
    .map(|secret| C::read_F(&mut Cursor::new(hex::decode(secret).unwrap())).unwrap())
    .collect::<Vec<_>>();
  let verification_shares = shares.iter().map(|secret| C::generator() * secret).collect::<Vec<_>>();

  let mut keys = HashMap::new();
  for i in 1 ..= u16::try_from(shares.len()).unwrap() {
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

    let these_keys = FrostCore::<C>::deserialize(&mut Cursor::new(serialized)).unwrap();
    assert_eq!(these_keys.params().t(), vectors.threshold);
    assert_eq!(usize::from(these_keys.params().n()), shares.len());
    assert_eq!(these_keys.params().i(), i);
    assert_eq!(these_keys.secret_share(), shares[usize::from(i - 1)]);
    assert_eq!(hex::encode(these_keys.group_key().to_bytes().as_ref()), vectors.group_key);
    keys.insert(i, FrostKeys::new(these_keys));
  }

  keys
}

pub fn test_with_vectors<R: RngCore + CryptoRng, C: Curve, H: Hram<C>>(
  rng: &mut R,
  vectors: Vectors,
) {
  // Do basic tests before trying the vectors
  test_curve::<_, C>(&mut *rng);
  test_schnorr::<_, C>(&mut *rng);
  test_promotion::<_, C>(rng);

  // Test against the vectors
  let keys = vectors_to_multisig_keys::<C>(&vectors);
  let group_key = C::read_G(&mut Cursor::new(hex::decode(&vectors.group_key).unwrap())).unwrap();
  let secret = C::read_F(&mut Cursor::new(hex::decode(&vectors.group_secret).unwrap())).unwrap();
  assert_eq!(C::generator() * secret, group_key);
  assert_eq!(recover(&keys), secret);

  let mut machines = vec![];
  for i in &vectors.included {
    machines.push((
      i,
      AlgorithmMachine::new(
        Schnorr::<C, H>::new(),
        keys[i].clone(),
        &vectors.included.to_vec().clone(),
      )
      .unwrap(),
    ));
  }

  let mut commitments = HashMap::new();
  let mut c = 0;
  let mut machines = machines
    .drain(..)
    .map(|(i, machine)| {
      let nonces = [
        C::read_F(&mut Cursor::new(hex::decode(&vectors.nonces[c][0]).unwrap())).unwrap(),
        C::read_F(&mut Cursor::new(hex::decode(&vectors.nonces[c][1]).unwrap())).unwrap(),
      ];
      c += 1;
      let these_commitments = vec![[C::generator() * nonces[0], C::generator() * nonces[1]]];
      let machine = machine.unsafe_override_preprocess(PreprocessPackage {
        nonces: vec![nonces],
        commitments: vec![these_commitments.clone()],
        addendum: vec![],
      });

      commitments.insert(
        *i,
        Cursor::new(
          [
            these_commitments[0][0].to_bytes().as_ref(),
            these_commitments[0][1].to_bytes().as_ref(),
          ]
          .concat()
          .to_vec(),
        ),
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

      assert_eq!(share, hex::decode(&vectors.sig_shares[c]).unwrap());
      c += 1;

      shares.insert(*i, Cursor::new(share));
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
