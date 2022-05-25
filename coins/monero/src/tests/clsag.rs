#[cfg(feature = "multisig")]
use std::{cell::RefCell, rc::Rc};

use rand::{RngCore, rngs::OsRng};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use crate::{
  Commitment,
  random_scalar, generate_key_image,
  wallet::Decoys,
  ringct::clsag::{ClsagInput, Clsag}
};
#[cfg(feature = "multisig")]
use crate::{frost::{Ed25519, MultisigError, Transcript}, ringct::clsag::{ClsagDetails, ClsagMultisig}};

#[cfg(feature = "multisig")]
use frost::tests::{key_gen, algorithm_machines, sign};

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
  let keys = key_gen::<_, Ed25519>(&mut OsRng);

  let randomness = random_scalar(&mut OsRng);
  let mut ring = vec![];
  for i in 0 .. RING_LEN {
    let dest;
    let mask;
    let amount;
    if i != u64::from(RING_INDEX) {
      dest = &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE;
      mask = random_scalar(&mut OsRng);
      amount = OsRng.next_u64();
    } else {
      dest = keys[&1].group_key().0;
      mask = randomness;
      amount = AMOUNT;
    }
    ring.push([dest, Commitment::new(mask, amount).calculate()]);
  }

  let mask_sum = random_scalar(&mut OsRng);
  sign(
    &mut OsRng,
    algorithm_machines(
      &mut OsRng,
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
      &keys
    ),
    &[1; 32]
  );

  Ok(())
}
