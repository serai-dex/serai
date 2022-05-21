#![cfg(feature = "multisig")]

use rand::rngs::OsRng;

use ff::Field;
use dalek_ff_group::{ED25519_BASEPOINT_TABLE, Scalar};

pub use frost::{
  FrostError, MultisigParams, MultisigKeys,
  key_gen, algorithm::Algorithm, sign::{self, lagrange}
};

use crate::frost::Ed25519;

pub const THRESHOLD: usize = 3;
pub const PARTICIPANTS: usize = 5;

pub fn generate_keys() -> (Vec<MultisigKeys<Ed25519>>, Scalar) {
  let mut params = vec![];
  let mut machines = vec![];
  let mut commitments = vec![vec![]];
  for i in 1 ..= PARTICIPANTS {
    params.push(
      MultisigParams::new(THRESHOLD, PARTICIPANTS, i).unwrap()
    );
    machines.push(
      key_gen::StateMachine::<Ed25519>::new(
        params[i - 1],
        "monero-sign-rs test suite".to_string()
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

  let mut keys = vec![];
  for i in 1 ..= PARTICIPANTS {
    let mut our_secret_shares = vec![vec![]];
    our_secret_shares.extend(
      secret_shares.iter().map(|shares| shares[i].clone()).collect::<Vec<Vec<u8>>>()
    );
    keys.push(machines[i - 1].complete(our_secret_shares).unwrap().clone());
  }

  let mut group_private = Scalar::zero();
  for i in 1 ..= THRESHOLD {
    group_private += keys[i - 1].secret_share() * lagrange::<Scalar>(
      i,
      &(1 ..= THRESHOLD).collect::<Vec<usize>>()
    );
  }
  assert_eq!(&ED25519_BASEPOINT_TABLE * group_private, keys[0].group_key());

  (keys, group_private)
}

#[allow(dead_code)] // Currently has some false positive
pub fn sign<S, M: sign::StateMachine<Signature = S>>(machines: &mut Vec<M>, msg: &[u8]) -> Vec<S> {
  assert!(machines.len() >= THRESHOLD);

  let mut commitments = Vec::with_capacity(PARTICIPANTS + 1);
  commitments.resize(PARTICIPANTS + 1, None);
  for i in 1 ..= THRESHOLD {
    commitments[i] = Some(machines[i - 1].preprocess(&mut OsRng).unwrap());
  }

  let mut shares = Vec::with_capacity(PARTICIPANTS + 1);
  shares.resize(PARTICIPANTS + 1, None);
  for i in 1 ..= THRESHOLD {
    shares[i] = Some(
      machines[i - 1].sign(
        &commitments
          .iter()
          .enumerate()
          .map(|(idx, value)| if idx == i { None } else { value.to_owned() })
          .collect::<Vec<Option<Vec<u8>>>>(),
        msg
      ).unwrap()
    );
  }

  let mut res = Vec::with_capacity(THRESHOLD);
  for i in 1 ..= THRESHOLD {
    res.push(
      machines[i - 1].complete(
        &shares
          .iter()
          .enumerate()
          .map(|(idx, value)| if idx == i { None } else { value.to_owned() })
          .collect::<Vec<Option<Vec<u8>>>>()
      ).unwrap()
    );
  }
  res
}
