#[cfg(feature = "multisig")]
use std::{cell::RefCell, rc::Rc};

use rand::{RngCore, rngs::OsRng};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use crate::{
  Commitment,
  random_scalar, generate_key_image,
  wallet::Decoys,
  clsag::{ClsagInput, Clsag}
};
#[cfg(feature = "multisig")]
use crate::{frost::{MultisigError, Transcript}, clsag::{ClsagDetails, ClsagMultisig}};

#[cfg(feature = "multisig")]
use crate::tests::frost::{THRESHOLD, generate_keys, sign};

const RING_LEN: u64 = 11;
const AMOUNT: u64 = 1337;

#[cfg(feature = "multisig")]
const RING_INDEX: u8 = 3;

#[test]
fn clsag() {
  for real in 0 .. RING_LEN {
    let msg = [1; 32];

    let mut secrets = [Scalar::zero(), Scalar::zero()];
    let mut ring = vec![];
    for i in 0 .. RING_LEN {
      let dest = random_scalar(&mut OsRng);
      let mask = random_scalar(&mut OsRng);
      let amount;
      if i == u64::from(real) {
        secrets = [dest, mask];
        amount = AMOUNT;
      } else {
        amount = OsRng.next_u64();
      }
      ring.push([&dest * &ED25519_BASEPOINT_TABLE, Commitment::new(mask, amount).calculate()]);
    }

    let image = generate_key_image(&secrets[0]);
    let (clsag, pseudo_out) = Clsag::sign(
      &mut OsRng,
      &vec![(
        secrets[0],
        image,
        ClsagInput::new(
          Commitment::new(secrets[1], AMOUNT),
          Decoys {
            i: u8::try_from(real).unwrap(),
            offsets: (1 ..= RING_LEN).into_iter().collect(),
            ring: ring.clone()
          }
        ).unwrap()
      )],
      random_scalar(&mut OsRng),
      msg
    ).swap_remove(0);
    clsag.verify(&ring, &image, &pseudo_out, &msg).unwrap();
    #[cfg(feature = "experimental")]
    clsag.rust_verify(&ring, &image, &pseudo_out, &msg).unwrap();
  }
}

#[cfg(feature = "multisig")]
#[test]
fn clsag_multisig() -> Result<(), MultisigError> {
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

  let mask_sum = random_scalar(&mut OsRng);
  let mut machines = Vec::with_capacity(t);
  for i in 1 ..= t {
    machines.push(
      sign::AlgorithmMachine::new(
        ClsagMultisig::new(
          Transcript::new(b"Monero Serai CLSAG Test".to_vec()),
          Rc::new(RefCell::new(Some(
            ClsagDetails::new(
              ClsagInput::new(
                Commitment::new(randomness, AMOUNT),
                Decoys {
                  i: RING_INDEX,
                  offsets: (1 ..= RING_LEN).into_iter().collect(),
                  ring: ring.clone()
                }
              ).unwrap(),
              mask_sum
            )
          )))
        ).unwrap(),
        Rc::new(keys[i - 1].clone()),
        &(1 ..= THRESHOLD).collect::<Vec<usize>>()
      ).unwrap()
    );
  }

  let mut signatures = sign(&mut machines, &[1; 32]);
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
