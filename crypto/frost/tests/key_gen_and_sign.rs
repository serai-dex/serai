use std::rc::Rc;

use rand::{RngCore, rngs::OsRng};

use digest::Digest;
use sha2::Sha256;

use frost::{
  Curve,
  MultisigParams, MultisigKeys,
  key_gen,
  algorithm::{Algorithm, Schnorr, SchnorrSignature},
  sign::{StateMachine, AlgorithmMachine}
};

mod common;
use common::{Secp256k1, TestHram};

const PARTICIPANTS: usize = 8;

fn sign<C: Curve, A: Algorithm<C, Signature = SchnorrSignature<C>>>(
  algorithm: A,
  keys: Vec<Rc<MultisigKeys<C>>>
) {
  let t = keys[0].params().t();
  let mut machines = vec![];
  let mut commitments = Vec::with_capacity(PARTICIPANTS + 1);
  commitments.resize(PARTICIPANTS + 1, None);
  for i in 1 ..= t {
    machines.push(
      AlgorithmMachine::new(
        algorithm.clone(),
        keys[i - 1].clone(),
        &(1 ..= t).collect::<Vec<usize>>()
      ).unwrap()
    );
    commitments[i] = Some(machines[i - 1].preprocess(&mut OsRng).unwrap());
  }

  let mut shares = Vec::with_capacity(PARTICIPANTS + 1);
  shares.resize(PARTICIPANTS + 1, None);
  for i in 1 ..= t {
    shares[i] = Some(
      machines[i - 1].sign(
        &commitments
          .iter()
          .enumerate()
          .map(|(idx, value)| if idx == i { None } else { value.to_owned() })
          .collect::<Vec<Option<Vec<u8>>>>(),
        b"Hello World"
      ).unwrap()
    );
  }

  let mut signature = None;
  for i in 1 ..= t {
    let sig = machines[i - 1].complete(
      &shares
        .iter()
        .enumerate()
        .map(|(idx, value)| if idx == i { None } else { value.to_owned() })
        .collect::<Vec<Option<Vec<u8>>>>()
    ).unwrap();
    if signature.is_none() {
      signature = Some(sig);
    }
    assert_eq!(sig, signature.unwrap());
  }
}

#[test]
fn key_gen_and_sign() {
  let mut params = vec![];
  let mut machines = vec![];
  let mut commitments = vec![vec![]];
  for i in 1 ..= PARTICIPANTS {
    params.push(
      MultisigParams::new(
        ((PARTICIPANTS / 3) * 2) + 1,
        PARTICIPANTS,
        i
      ).unwrap()
    );
    machines.push(
      key_gen::StateMachine::<Secp256k1>::new(
        params[i - 1],
        "FF/Group Rust key_gen test".to_string()
      )
    );
    commitments.push(machines[i - 1].generate_coefficients(&mut OsRng).unwrap());
  }

  let mut secret_shares = vec![];
  for i in 1 ..= PARTICIPANTS {
    secret_shares.push(
      machines[i - 1].generate_secret_shares(
        &mut OsRng,
        commitments
          .iter()
          .enumerate()
          .map(|(idx, commitments)| if idx == i { vec![] } else { commitments.to_vec() })
          .collect()
      ).unwrap()
    );
  }

  let mut verification_shares = vec![];
  let mut group_key = None;
  let mut keys = vec![];
  for i in 1 ..= PARTICIPANTS {
    let mut our_secret_shares = vec![vec![]];
    our_secret_shares.extend(
      secret_shares.iter().map(|shares| shares[i].clone()).collect::<Vec<Vec<u8>>>()
    );

    let these_keys = machines[i - 1].complete(our_secret_shares).unwrap();
    assert_eq!(
      MultisigKeys::<Secp256k1>::deserialize(&these_keys.serialize()).unwrap(),
      these_keys
    );
    keys.push(Rc::new(these_keys.clone()));

    if verification_shares.len() == 0 {
      verification_shares = these_keys.verification_shares();
    }
    assert_eq!(verification_shares, these_keys.verification_shares());

    if group_key.is_none() {
      group_key = Some(these_keys.group_key());
    }
    assert_eq!(group_key.unwrap(), these_keys.group_key());
  }

  sign(Schnorr::<Secp256k1, TestHram>::new(), keys.clone());

  let mut randomization = [0; 64];
  (&mut OsRng).fill_bytes(&mut randomization);
  sign(
    Schnorr::<Secp256k1, TestHram>::new(),
    keys.iter().map(
      |keys| Rc::new(keys.offset(Secp256k1::hash_to_F(&Sha256::digest(&randomization))))
    ).collect()
  );
}
