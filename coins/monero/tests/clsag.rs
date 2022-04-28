use rand::{RngCore, rngs::OsRng};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use monero_serai::{SignError, random_scalar, commitment, key_image, clsag};

#[cfg(feature = "multisig")]
use ::frost::sign;

#[cfg(feature = "multisig")]
mod frost;
#[cfg(feature = "multisig")]
use crate::frost::generate_keys;

#[cfg(feature = "multisig")]
const THRESHOLD: usize = 5;
#[cfg(feature = "multisig")]
const PARTICIPANTS: usize = 8;

const RING_INDEX: u8 = 3;
const RING_LEN: u64 = 11;
const AMOUNT: u64 = 1337;

#[test]
fn test_single() -> Result<(), SignError> {
  let msg = [1; 32];

  let mut secrets = [Scalar::zero(), Scalar::zero()];
  let mut ring = vec![];
  for i in 0 .. RING_LEN {
    let dest = random_scalar(&mut OsRng);
    let a = random_scalar(&mut OsRng);
    let amount;
    if i == u64::from(RING_INDEX) {
      secrets = [dest, a];
      amount = AMOUNT;
    } else {
      amount = OsRng.next_u64();
    }
    let mask = commitment(&a, amount);
    ring.push([&dest * &ED25519_BASEPOINT_TABLE, mask]);
  }

  let image = key_image::single(&secrets[0]);
  let (clsag, pseudo_out) = clsag::sign(
    &mut OsRng,
    image,
    msg,
    ring.clone(),
    RING_INDEX,
    &secrets[0],
    &secrets[1],
    AMOUNT
  )?;
  clsag::verify(&clsag, image, &msg, &ring, pseudo_out)?;
  Ok(())
}

#[cfg(feature = "multisig")]
#[test]
fn test_multisig() -> Result<(), SignError> {
  let (keys, group_private) = generate_keys(THRESHOLD, PARTICIPANTS);
  let t = keys[0].params().t();

  let mut images = vec![];
  images.resize(PARTICIPANTS + 1, None);
  let included = (1 ..= THRESHOLD).collect::<Vec<usize>>();
  for i in &included {
    let i = *i;
    images[i] = Some(
      (
        keys[0].verification_shares()[i].0,
        key_image::multisig(&mut OsRng, &keys[i - 1], &included)
      )
    );
  }

  let msg = [1; 32];

  images.push(None);
  let ki_used = images.swap_remove(1).unwrap().1;
  let image = ki_used.resolve(images).unwrap();

  let randomness = random_scalar(&mut OsRng);
  let mut ring = vec![];
  for i in 0 .. RING_LEN {
    let dest;
    let a;
    let amount;
    if i != u64::from(RING_INDEX) {
      dest = random_scalar(&mut OsRng);
      a = random_scalar(&mut OsRng);
      amount = OsRng.next_u64();
    } else {
      dest = group_private.0;
      a = randomness;
      amount = AMOUNT;
    }
    let mask = commitment(&a, amount);
    ring.push([&dest * &ED25519_BASEPOINT_TABLE, mask]);
  }

  let mut machines = vec![];
  let mut commitments = Vec::with_capacity(PARTICIPANTS + 1);
  commitments.resize(PARTICIPANTS + 1, None);
  for i in 1 ..= t {
    machines.push(
      sign::StateMachine::new(
        sign::Params::new(
          clsag::Multisig::new(image, msg, ring.clone(), RING_INDEX, &randomness, AMOUNT).unwrap(),
          keys[i - 1].clone(),
          &(1 ..= t).collect::<Vec<usize>>()
        ).unwrap()
      )
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
        &vec![]
      ).unwrap()
    );
  }

  let mut signature = None;
  for i in 1 ..= t {
    // Multisig does call verify to ensure integrity upon complete, before checking individual key
    // shares. For FROST Schnorr, it's cheaper. For CLSAG, it may be more expensive? Yet it ensures
    // we have usable signatures, not just signatures we think are usable
    let sig = machines[i - 1].complete(
      &shares
        .iter()
        .enumerate()
        .map(|(idx, value)| if idx == i { None } else { value.to_owned() })
        .collect::<Vec<Option<Vec<u8>>>>()
    ).unwrap();
    if signature.is_none() {
      signature = Some(sig.clone());
    }
    // Check the commitment out and the non-decoy s scalar are identical to every other signature
    assert_eq!(sig.1, signature.as_ref().unwrap().1);
    assert_eq!(sig.0.s[RING_INDEX as usize], signature.as_ref().unwrap().0.s[RING_INDEX as usize]);
  }

  Ok(())
}
