#![cfg(feature = "multisig")]

use std::rc::Rc;

use rand::rngs::OsRng;

use ff::Field;
use dalek_ff_group::{ED25519_BASEPOINT_TABLE, Scalar};

use frost::{
  MultisigParams, MultisigKeys,
  key_gen,
  sign::lagrange
};

use monero_sign::frost::Ed25519;

pub fn generate_keys(t: usize, n: usize) -> (Vec<Rc<MultisigKeys<Ed25519>>>, Scalar) {
  let mut params = vec![];
  let mut machines = vec![];
  let mut commitments = vec![vec![]];
  for i in 1 ..= n {
    params.push(
      MultisigParams::new(t, n, i).unwrap()
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
  for i in 1 ..= n {
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
  for i in 1 ..= n {
    let mut our_secret_shares = vec![vec![]];
    our_secret_shares.extend(
      secret_shares.iter().map(|shares| shares[i].clone()).collect::<Vec<Vec<u8>>>()
    );
    keys.push(Rc::new(machines[i - 1].complete(our_secret_shares).unwrap().clone()));
  }

  let mut group_private = Scalar::zero();
  for i in 0 .. t {
    group_private += keys[i].secret_share() * lagrange::<Scalar>(i + 1, &(1 ..= t).collect::<Vec<usize>>());
  }
  assert_eq!(&ED25519_BASEPOINT_TABLE * group_private, keys[0].group_key());

  (keys, group_private)
}
