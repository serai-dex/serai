use rand::{RngCore, SeedableRng, rngs::OsRng};
use rand_chacha::ChaCha12Rng;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use monero_serai::{random_scalar, Commitment, frost::MultisigError, key_image, clsag};

#[cfg(feature = "multisig")]
mod frost;
#[cfg(feature = "multisig")]
use crate::frost::{THRESHOLD, PARTICIPANTS, generate_keys, sign};

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
        image,
        ring.clone(),
        RING_INDEX,
        Commitment::new(secrets[1], AMOUNT)
      ).unwrap()
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

  let mut algorithms = Vec::with_capacity(t);
  for _ in 1 ..= t {
    algorithms.push(
      clsag::Multisig::new(
        &mut ChaCha12Rng::seed_from_u64(1),
        msg,
        clsag::Input::new(image, ring.clone(), RING_INDEX, Commitment::new(randomness, AMOUNT)).unwrap()
      ).unwrap()
    );
  }

  let mut signatures = sign(algorithms, keys);
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
