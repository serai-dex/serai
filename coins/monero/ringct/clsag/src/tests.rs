use core::ops::Deref;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

#[cfg(feature = "multisig")]
use transcript::{Transcript, RecommendedTranscript};
#[cfg(feature = "multisig")]
use frost::curve::Ed25519;

use monero_generators::hash_to_point;
use monero_primitives::{Commitment, Decoys};
use crate::{ClsagContext, Clsag};
#[cfg(feature = "multisig")]
use crate::ClsagMultisig;

#[cfg(feature = "multisig")]
use frost::{
  Participant,
  tests::{key_gen, algorithm_machines, sign},
};

const RING_LEN: u64 = 11;
const AMOUNT: u64 = 1337;

#[cfg(feature = "multisig")]
const RING_INDEX: u8 = 3;

#[test]
fn clsag() {
  for real in 0 .. RING_LEN {
    let msg = [1; 32];

    let mut secrets = (Zeroizing::new(Scalar::ZERO), Scalar::ZERO);
    let mut ring = vec![];
    for i in 0 .. RING_LEN {
      let dest = Zeroizing::new(Scalar::random(&mut OsRng));
      let mask = Scalar::random(&mut OsRng);
      let amount;
      if i == real {
        secrets = (dest.clone(), mask);
        amount = AMOUNT;
      } else {
        amount = OsRng.next_u64();
      }
      ring
        .push([dest.deref() * ED25519_BASEPOINT_TABLE, Commitment::new(mask, amount).calculate()]);
    }

    let (mut clsag, pseudo_out) = Clsag::sign(
      &mut OsRng,
      vec![(
        secrets.0.clone(),
        ClsagContext::new(
          Decoys::new((1 ..= RING_LEN).collect(), u8::try_from(real).unwrap(), ring.clone())
            .unwrap(),
          Commitment::new(secrets.1, AMOUNT),
        )
        .unwrap(),
      )],
      Scalar::random(&mut OsRng),
      msg,
    )
    .unwrap()
    .swap_remove(0);

    let image =
      hash_to_point((ED25519_BASEPOINT_TABLE * secrets.0.deref()).compress().0) * secrets.0.deref();
    clsag.verify(&ring, &image, &pseudo_out, &msg).unwrap();

    // make sure verification fails if we throw a random `c1` at it.
    clsag.c1 = Scalar::random(&mut OsRng);
    assert!(clsag.verify(&ring, &image, &pseudo_out, &msg).is_err());
  }
}

#[cfg(feature = "multisig")]
#[test]
fn clsag_multisig() {
  let keys = key_gen::<_, Ed25519>(&mut OsRng);

  let randomness = Scalar::random(&mut OsRng);
  let mut ring = vec![];
  for i in 0 .. RING_LEN {
    let dest;
    let mask;
    let amount;
    if i != u64::from(RING_INDEX) {
      dest = &Scalar::random(&mut OsRng) * ED25519_BASEPOINT_TABLE;
      mask = Scalar::random(&mut OsRng);
      amount = OsRng.next_u64();
    } else {
      dest = keys[&Participant::new(1).unwrap()].group_key().0;
      mask = randomness;
      amount = AMOUNT;
    }
    ring.push([dest, Commitment::new(mask, amount).calculate()]);
  }

  let (algorithm, mask_send) = ClsagMultisig::new(
    RecommendedTranscript::new(b"Monero Serai CLSAG Test"),
    ClsagContext::new(
      Decoys::new((1 ..= RING_LEN).collect(), RING_INDEX, ring.clone()).unwrap(),
      Commitment::new(randomness, AMOUNT),
    )
    .unwrap(),
  );
  mask_send.send(Scalar::random(&mut OsRng));

  sign(
    &mut OsRng,
    &algorithm,
    keys.clone(),
    algorithm_machines(&mut OsRng, &algorithm, &keys),
    &[1; 32],
  );
}
