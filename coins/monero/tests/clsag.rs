#[cfg(feature = "multisig")]
use std::{rc::Rc, cell::RefCell};

use rand::{RngCore, rngs::OsRng};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use monero::VarInt;

use monero_serai::{Commitment, random_scalar, generate_key_image, transaction::decoys::Decoys, clsag};
#[cfg(feature = "multisig")]
use monero_serai::frost::{MultisigError, Transcript};

#[cfg(feature = "multisig")]
mod frost;
#[cfg(feature = "multisig")]
use crate::frost::{THRESHOLD, generate_keys, sign};

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
    let (clsag, pseudo_out) = clsag::sign(
      &mut OsRng,
      &vec![(
        secrets[0],
        image,
        clsag::Input::new(
          Commitment::new(secrets[1], AMOUNT),
          Decoys {
            i: u8::try_from(real).unwrap(),
            offsets: (1 ..= RING_LEN).into_iter().map(|o| VarInt(o)).collect(),
            ring: ring.clone()
          }
        ).unwrap()
      )],
      random_scalar(&mut OsRng),
      msg
    ).unwrap().swap_remove(0);
    clsag::verify(&clsag, &ring, &image, &pseudo_out, &msg).unwrap();
    #[cfg(feature = "experimental")]
    clsag::rust_verify(&clsag, &ring, &image, &pseudo_out, &msg).unwrap();
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
        clsag::Multisig::new(
          Transcript::new(b"Monero Serai CLSAG Test".to_vec()),
          Rc::new(RefCell::new(Some(
            clsag::Details::new(
              clsag::Input::new(
                Commitment::new(randomness, AMOUNT),
                Decoys {
                  i: RING_INDEX,
                  offsets: (1 ..= RING_LEN).into_iter().map(|o| VarInt(o)).collect(),
                  ring: ring.clone()
                }
              ).unwrap(),
              mask_sum
            )
          ))),
          Rc::new(RefCell::new(Some([1; 32])))
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
