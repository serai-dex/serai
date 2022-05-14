#![allow(non_snake_case)]

use lazy_static::lazy_static;
use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  traits::VartimePrecomputedMultiscalarMul,
  edwards::{EdwardsPoint, VartimeEdwardsPrecomputation}
};
#[cfg(feature = "experimental")]
use curve25519_dalek::edwards::CompressedEdwardsY;

use monero::{consensus::Encodable, util::ringct::{Key, Clsag}};

use crate::{
  Commitment,
  transaction::decoys::Decoys,
  random_scalar,
  hash_to_scalar,
  hash_to_point
};

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use multisig::{Details, Multisig};

#[derive(Error, Debug)]
pub enum Error {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("invalid ring member (member {0}, ring size {1})")]
  InvalidRingMember(u8, u8),
  #[error("invalid commitment")]
  InvalidCommitment,
  #[error("invalid D")]
  InvalidD,
  #[error("invalid s")]
  InvalidS,
  #[error("invalid c1")]
  InvalidC1
}

#[derive(Clone, Debug)]
pub struct Input {
  // The actual commitment for the true spend
  pub commitment: Commitment,
  // True spend index, offsets, and ring
  pub decoys: Decoys
}

lazy_static! {
  static ref INV_EIGHT: Scalar = Scalar::from(8 as u8).invert();
}

impl Input {
  pub fn new(
    commitment: Commitment,
    decoys: Decoys
  ) -> Result<Input, Error> {
    let n = decoys.len();
    if n > u8::MAX.into() {
      Err(Error::InternalError("max ring size in this library is u8 max".to_string()))?;
    }
    if decoys.i >= (n as u8) {
      Err(Error::InvalidRingMember(decoys.i, n as u8))?;
    }

    // Validate the commitment matches
    if decoys.ring[usize::from(decoys.i)][1] != commitment.calculate() {
      Err(Error::InvalidCommitment)?;
    }

    Ok(Input { commitment, decoys })
  }
}

enum Mode {
  Sign(usize, EdwardsPoint, EdwardsPoint),
  #[cfg(feature = "experimental")]
  Verify(Scalar)
}

fn core(
  ring: &[[EdwardsPoint; 2]],
  I: &EdwardsPoint,
  pseudo_out: &EdwardsPoint,
  msg: &[u8; 32],
  D: &EdwardsPoint,
  s: &[Scalar],
  // Use a Result as Either for sign/verify
  A_c1: Mode
) -> (([u8; 32], Scalar, Scalar), Scalar) {
  let n = ring.len();

  // Doesn't use a constant time table as dalek takes longer to generate those then they save
  let images_precomp = VartimeEdwardsPrecomputation::new([I, D]);
  let D = D * *INV_EIGHT;

  let mut to_hash = vec![];
  to_hash.reserve_exact(((2 * n) + 5) * 32);
  const PREFIX: &str = "CLSAG_";
  const AGG_0:  &str = "CLSAG_agg_0";
  const ROUND:  &str =       "round";
  to_hash.extend(AGG_0.bytes());
  to_hash.extend([0; 32 - AGG_0.len()]);

  let mut P = vec![];
  P.reserve_exact(n);
  let mut C = vec![];
  C.reserve_exact(n);
  for member in ring {
    P.push(member[0]);
    C.push(member[1] - pseudo_out);
  }

  for member in ring {
    to_hash.extend(member[0].compress().to_bytes());
  }

  for member in ring {
    to_hash.extend(member[1].compress().to_bytes());
  }

  to_hash.extend(I.compress().to_bytes());
  let D_bytes = D.compress().to_bytes();
  to_hash.extend(D_bytes);
  to_hash.extend(pseudo_out.compress().to_bytes());
  let mu_P = hash_to_scalar(&to_hash);
  to_hash[AGG_0.len() - 1] = '1' as u8;
  let mu_C = hash_to_scalar(&to_hash);

  to_hash.truncate(((2 * n) + 1) * 32);
  for i in 0 .. ROUND.len() {
    to_hash[PREFIX.len() + i] = ROUND.as_bytes()[i] as u8;
  }
  to_hash.extend(pseudo_out.compress().to_bytes());
  to_hash.extend(msg);

  let start;
  let end;
  let mut c;
  match A_c1 {
    Mode::Sign(r, A, AH) => {
      start = r + 1;
      end = r + n;
      to_hash.extend(A.compress().to_bytes());
      to_hash.extend(AH.compress().to_bytes());
      c = hash_to_scalar(&to_hash);
    },

    #[cfg(feature = "experimental")]
    Mode::Verify(c1) => {
      start = 0;
      end = n;
      c = c1;
    }
  }

  let mut c1 = None;
  for i in (start .. end).map(|i| i % n) {
    if i == 0 {
      c1 = Some(c);
    }

    let c_p = mu_P * c;
    let c_c = mu_C * c;

    let L = (&s[i] * &ED25519_BASEPOINT_TABLE) + (c_p * P[i]) + (c_c * C[i]);
    let PH = hash_to_point(&P[i]);
    // Shouldn't be an issue as all of the variables in this vartime statement are public
    let R = (s[i] * PH) + images_precomp.vartime_multiscalar_mul(&[c_p, c_c]);

    to_hash.truncate(((2 * n) + 3) * 32);
    to_hash.extend(L.compress().to_bytes());
    to_hash.extend(R.compress().to_bytes());
    c = hash_to_scalar(&to_hash);
  }

  ((D_bytes, c * mu_P, c * mu_C), c1.unwrap_or(c))
}

pub(crate) fn sign_core<R: RngCore + CryptoRng>(
  rng: &mut R,
  I: &EdwardsPoint,
  input: &Input,
  mask: Scalar,
  msg: &[u8; 32],
  A: EdwardsPoint,
  AH: EdwardsPoint
) -> (Clsag, EdwardsPoint, Scalar, Scalar) {
  let r: usize = input.decoys.i.into();

  let pseudo_out = Commitment::new(mask, input.commitment.amount).calculate();
  let z = input.commitment.mask - mask;

  let H = hash_to_point(&input.decoys.ring[r][0]);
  let D = H * z;
  let mut s = Vec::with_capacity(input.decoys.ring.len());
  for _ in 0 .. input.decoys.ring.len() {
    s.push(random_scalar(rng));
  }
  let ((D_bytes, p, c), c1) = core(&input.decoys.ring, I, &pseudo_out, msg, &D, &s, Mode::Sign(r, A, AH));

  (
    Clsag {
      D: Key { key: D_bytes },
      s: s.iter().map(|s| Key { key: s.to_bytes() }).collect(),
      c1: Key { key: c1.to_bytes() }
    },
    pseudo_out,
    p,
    c * z
  )
}

pub fn sign<R: RngCore + CryptoRng>(
  rng: &mut R,
  inputs: &[(Scalar, EdwardsPoint, Input)],
  sum_outputs: Scalar,
  msg: [u8; 32]
) -> Option<Vec<(Clsag, EdwardsPoint)>> {
  if inputs.len() == 0 {
    return None;
  }

  let nonce = random_scalar(rng);
  let mut rand_source = [0; 64];
  rng.fill_bytes(&mut rand_source);

  let mut res = Vec::with_capacity(inputs.len());
  let mut sum_pseudo_outs = Scalar::zero();
  for i in 0 .. inputs.len() {
    let mut mask = random_scalar(rng);
    if i == (inputs.len() - 1) {
      mask = sum_outputs - sum_pseudo_outs;
    } else {
      sum_pseudo_outs += mask;
    }

    let mut rand_source = [0; 64];
    rng.fill_bytes(&mut rand_source);
    let (mut clsag, pseudo_out, p, c) = sign_core(
      rng,
      &inputs[i].1,
      &inputs[i].2,
      mask,
      &msg,
      &nonce * &ED25519_BASEPOINT_TABLE,
      nonce * hash_to_point(&inputs[i].2.decoys.ring[usize::from(inputs[i].2.decoys.i)][0])
    );
    clsag.s[inputs[i].2.decoys.i as usize] = Key {
      key: (nonce - ((p * inputs[i].0) + c)).to_bytes()
    };

    res.push((clsag, pseudo_out));
  }

  Some(res)
}

// Not extensively tested nor guaranteed to have expected parity with Monero
#[cfg(feature = "experimental")]
pub fn rust_verify(
  clsag: &Clsag,
  ring: &[[EdwardsPoint; 2]],
  I: &EdwardsPoint,
  pseudo_out: &EdwardsPoint,
  msg: &[u8; 32]
) -> Result<(), Error> {
  let c1 = Scalar::from_canonical_bytes(clsag.c1.key).ok_or(Error::InvalidC1)?;
  let (_, c1_calculated) = core(
    ring,
    I,
    pseudo_out,
    msg,
    &CompressedEdwardsY(clsag.D.key).decompress().ok_or(Error::InvalidD)?.mul_by_cofactor(),
    &clsag.s.iter().map(|s| Scalar::from_canonical_bytes(s.key).ok_or(Error::InvalidS)).collect::<Result<Vec<_>, _>>()?,
    Mode::Verify(c1)
  );
  if c1_calculated != c1 {
    Err(Error::InvalidC1)?;
  }
  Ok(())
}

// Uses Monero's C verification function to ensure compatibility with Monero
#[link(name = "wrapper")]
extern "C" {
  pub(crate) fn c_verify_clsag(
    serialized_len: usize,
    serialized: *const u8,
    ring_size: u8,
    ring: *const u8,
    I: *const u8,
    pseudo_out: *const u8,
    msg: *const u8
  ) -> bool;
}

pub fn verify(
  clsag: &Clsag,
  ring: &[[EdwardsPoint; 2]],
  I: &EdwardsPoint,
  pseudo_out: &EdwardsPoint,
  msg: &[u8; 32]
) -> Result<(), Error> {
  // Workaround for the fact monero-rs doesn't include the length of clsag.s in clsag encoding
  // despite it being part of clsag encoding. Reason for the patch version pin
  let mut serialized = vec![clsag.s.len() as u8];
  clsag.consensus_encode(&mut serialized).unwrap();

  let I_bytes = I.compress().to_bytes();

  let mut ring_bytes = vec![];
  for member in ring {
    ring_bytes.extend(&member[0].compress().to_bytes());
    ring_bytes.extend(&member[1].compress().to_bytes());
  }

  let pseudo_out_bytes = pseudo_out.compress().to_bytes();

  unsafe {
    if c_verify_clsag(
      serialized.len(), serialized.as_ptr(),
      ring.len() as u8, ring_bytes.as_ptr(),
      I_bytes.as_ptr(), pseudo_out_bytes.as_ptr(), msg.as_ptr()
    ) {
      Ok(())
    } else {
      Err(Error::InvalidC1)
    }
  }
}
