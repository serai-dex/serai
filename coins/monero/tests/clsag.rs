use std::{rc::Rc, cell::RefCell};

use rand::{RngCore, rngs::OsRng};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use monero_serai::{random_scalar, Commitment, frost::MultisigError, key_image, clsag};

#[cfg(feature = "multisig")]
mod frost;
#[cfg(feature = "multisig")]
use crate::frost::{THRESHOLD, generate_keys, sign};

const RING_INDEX: u8 = 3;
const RING_LEN: u64 = 11;
const AMOUNT: u64 = 1337;

#[test]
fn test_single() {
  let msg = [1; 32];

  let mut secrets = [Scalar::zero(), Scalar::zero()];
  let mut ring = vec![];
  for i in 0 .. RING_LEN {
    let dest = random_scalar(&mut OsRng);
    let mask = random_scalar(&mut OsRng);
    let amount;
    if i == u64::from(RING_INDEX) {
      secrets = [dest, mask];
      amount = AMOUNT;
    } else {
      amount = OsRng.next_u64();
    }
    ring.push([&dest * &ED25519_BASEPOINT_TABLE, Commitment::new(mask, amount).calculate()]);
  }

  let image = key_image::generate(&secrets[0]);
  let (clsag, pseudo_out) = clsag::sign(
    &mut OsRng,
    msg,
    &vec![(
      secrets[0],
      clsag::Input::new(
        ring.clone(),
        RING_INDEX,
        Commitment::new(secrets[1], AMOUNT)
      ).unwrap(),
      image
    )],
    Scalar::zero()
  ).unwrap().swap_remove(0);
  assert!(clsag::verify(&clsag, &msg, image, &ring, pseudo_out));
}

#[cfg(feature = "multisig")]
#[test]
fn test_multisig() -> Result<(), MultisigError> {
  let (keys, group_private) = generate_keys();
  let t = keys[0].params().t();

  let randomness = random_scalar(&mut OsRng);
  let mut ring = vec![];
  for i in 0 .. RING_LEN {
    let dest;
    let mask;
    let amount;
    if i != u64::from(RING_INDEX) {
      dest = random_scalar(&mut OsRng);
      mask = random_scalar(&mut OsRng);
      amount = OsRng.next_u64();
    } else {
      dest = group_private.0;
      mask = randomness;
      amount = AMOUNT;
    }
    ring.push([&dest * &ED25519_BASEPOINT_TABLE, Commitment::new(mask, amount).calculate()]);
  }

  let mut machines = Vec::with_capacity(t);
  for i in 1 ..= t {
    machines.push(
      sign::AlgorithmMachine::new(
        clsag::Multisig::new(
          clsag::Input::new(ring.clone(), RING_INDEX, Commitment::new(randomness, AMOUNT)).unwrap(),
          Rc::new(RefCell::new([1; 32])),
          Rc::new(RefCell::new(Scalar::from(42u64)))
        ).unwrap(),
        keys[i - 1].clone(),
        &(1 ..= THRESHOLD).collect::<Vec<usize>>()
      ).unwrap()
    );
  }

  let mut signatures = sign(&mut machines, keys);
  let signature = signatures.swap_remove(0);
  for s in 0 .. (t - 1) {
    // Verify the commitments and the non-decoy s scalar are identical to every other signature
    // FROST will already have called verify on the produced signature, before checking individual
    // key shares. For FROST Schnorr, it's cheaper. For CLSAG, it may be more expensive? Yet it
    // ensures we have usable signatures, not just signatures we think are usable
    assert_eq!(signatures[s].1, signature.1);
    assert_eq!(signatures[s].0.s[RING_INDEX as usize], signature.0.s[RING_INDEX as usize]);
  }

  Ok(())
}
