use std::{rc::Rc, collections::HashMap};

use crate::{
  Curve, MultisigKeys,
  algorithm::{Schnorr, Hram},
  sign::{PreprocessPackage, StateMachine, AlgorithmMachine},
  tests::recover
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

// Load these vectors into MultisigKeys using a custom serialization it'll deserialize
fn vectors_to_multisig_keys<C: Curve>(vectors: &Vectors) -> HashMap<u16, MultisigKeys<C>> {
  let shares = vectors.shares.iter().map(
    |secret| C::F_from_slice(&hex::decode(secret).unwrap()).unwrap()
  ).collect::<Vec<_>>();
  let verification_shares = shares.iter().map(
    |secret| C::generator() * secret
  ).collect::<Vec<_>>();

  let mut keys = HashMap::new();
  for i in 1 ..= u16::try_from(shares.len()).unwrap() {
    let mut serialized = vec![];
    serialized.push(C::id_len());
    serialized.extend(C::id());
    serialized.extend(vectors.threshold.to_be_bytes());
    serialized.extend(u16::try_from(shares.len()).unwrap().to_be_bytes());
    serialized.extend(i.to_be_bytes());
    serialized.extend(C::F_to_bytes(&shares[usize::from(i) - 1]));
    serialized.extend(&hex::decode(vectors.group_key).unwrap());
    for share in &verification_shares {
      serialized.extend(&C::G_to_bytes(share));
    }

    let these_keys = MultisigKeys::<C>::deserialize(&serialized).unwrap();
    assert_eq!(these_keys.params().t(), vectors.threshold);
    assert_eq!(usize::from(these_keys.params().n()), shares.len());
    assert_eq!(these_keys.params().i(), i);
    assert_eq!(these_keys.secret_share(), shares[usize::from(i - 1)]);
    assert_eq!(&hex::encode(&C::G_to_bytes(&these_keys.group_key())), vectors.group_key);
    keys.insert(i, these_keys);
  }

  keys
}

pub fn vectors<C: Curve, H: Hram<C>>(vectors: Vectors) {
  let keys = vectors_to_multisig_keys::<C>(&vectors);
  let group_key = C::G_from_slice(&hex::decode(vectors.group_key).unwrap()).unwrap();
  assert_eq!(
    C::generator() * C::F_from_slice(&hex::decode(vectors.group_secret).unwrap()).unwrap(),
    group_key
  );
  assert_eq!(
    recover(&keys),
    C::F_from_slice(&hex::decode(vectors.group_secret).unwrap()).unwrap()
  );

  let mut machines = vec![];
  for i in vectors.included {
    machines.push((
      *i,
      AlgorithmMachine::new(
        Schnorr::<C, H>::new(),
        Rc::new(keys[i].clone()),
        vectors.included.clone()
      ).unwrap()
    ));
  }

  let mut commitments = HashMap::new();
  let mut c = 0;
  for (i, machine) in machines.iter_mut() {
    let nonces = [
      C::F_from_slice(&hex::decode(vectors.nonces[c][0]).unwrap()).unwrap(),
      C::F_from_slice(&hex::decode(vectors.nonces[c][1]).unwrap()).unwrap()
    ];

    let mut serialized = C::G_to_bytes(&(C::generator() * nonces[0]));
    serialized.extend(&C::G_to_bytes(&(C::generator() * nonces[1])));

    machine.unsafe_override_preprocess(
      PreprocessPackage { nonces, serialized: serialized.clone() }
    );

    commitments.insert(*i, serialized);
    c += 1;
  }

  let mut shares = HashMap::new();
  c = 0;
  for (i, machine) in machines.iter_mut() {
    let share = machine.sign(commitments.clone(), &hex::decode(vectors.msg).unwrap()).unwrap();
    assert_eq!(share, hex::decode(vectors.sig_shares[c]).unwrap());
    shares.insert(*i, share);
    c += 1;
  }

  for (_, machine) in machines.iter_mut() {
    let sig = machine.complete(shares.clone()).unwrap();
    let mut serialized = C::G_to_bytes(&sig.R);
    serialized.extend(C::F_to_bytes(&sig.s));
    assert_eq!(hex::encode(serialized), vectors.sig);
  }
}
