#![allow(non_snake_case)]

use core::ops::Deref;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use subtle::{ConstantTimeEq, ConditionallySelectable};

use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_TABLE, ED25519_BASEPOINT_POINT},
  scalar::Scalar,
  traits::{IsIdentity, MultiscalarMul, VartimePrecomputedMultiscalarMul},
  edwards::{EdwardsPoint, VartimeEdwardsPrecomputation},
};

use crate::{
  INV_EIGHT, BASEPOINT_PRECOMP, Commitment, random_scalar, hash_to_scalar, wallet::decoys::Decoys,
  ringct::hash_to_point, serialize::*,
};

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use multisig::{ClsagDetails, ClsagAddendum, ClsagMultisig};
#[cfg(feature = "multisig")]
pub(crate) use multisig::add_key_image_share;

/// Errors returned when CLSAG signing fails.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum ClsagError {
  #[cfg_attr(feature = "std", error("internal error ({0})"))]
  InternalError(&'static str),
  #[cfg_attr(feature = "std", error("invalid ring"))]
  InvalidRing,
  #[cfg_attr(feature = "std", error("invalid ring member (member {0}, ring size {1})"))]
  InvalidRingMember(u8, u8),
  #[cfg_attr(feature = "std", error("invalid commitment"))]
  InvalidCommitment,
  #[cfg_attr(feature = "std", error("invalid key image"))]
  InvalidImage,
  #[cfg_attr(feature = "std", error("invalid D"))]
  InvalidD,
  #[cfg_attr(feature = "std", error("invalid s"))]
  InvalidS,
  #[cfg_attr(feature = "std", error("invalid c1"))]
  InvalidC1,
}

/// Input being signed for.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ClsagInput {
  // The actual commitment for the true spend
  pub(crate) commitment: Commitment,
  // True spend index, offsets, and ring
  pub(crate) decoys: Decoys,
}

impl ClsagInput {
  pub fn new(commitment: Commitment, decoys: Decoys) -> Result<ClsagInput, ClsagError> {
    let n = decoys.len();
    if n > u8::MAX.into() {
      Err(ClsagError::InternalError("max ring size in this library is u8 max"))?;
    }
    let n = u8::try_from(n).unwrap();
    if decoys.i >= n {
      Err(ClsagError::InvalidRingMember(decoys.i, n))?;
    }

    // Validate the commitment matches
    if decoys.ring[usize::from(decoys.i)][1] != commitment.calculate() {
      Err(ClsagError::InvalidCommitment)?;
    }

    Ok(ClsagInput { commitment, decoys })
  }
}

#[allow(clippy::large_enum_variant)]
enum Mode {
  Sign(usize, EdwardsPoint, EdwardsPoint),
  Verify(Scalar),
}

// Core of the CLSAG algorithm, applicable to both sign and verify with minimal differences
// Said differences are covered via the above Mode
fn core(
  ring: &[[EdwardsPoint; 2]],
  I: &EdwardsPoint,
  pseudo_out: &EdwardsPoint,
  msg: &[u8; 32],
  D: &EdwardsPoint,
  s: &[Scalar],
  A_c1: &Mode,
) -> ((EdwardsPoint, Scalar, Scalar), Scalar) {
  let n = ring.len();

  let images_precomp = match A_c1 {
    Mode::Sign(..) => None,
    Mode::Verify(..) => Some(VartimeEdwardsPrecomputation::new([I, D])),
  };
  let D_INV_EIGHT = D * INV_EIGHT();

  // Generate the transcript
  // Instead of generating multiple, a single transcript is created and then edited as needed
  const PREFIX: &[u8] = b"CLSAG_";
  #[rustfmt::skip]
  const AGG_0: &[u8]  =       b"agg_0";
  #[rustfmt::skip]
  const ROUND: &[u8]  =       b"round";
  const PREFIX_AGG_0_LEN: usize = PREFIX.len() + AGG_0.len();

  let mut to_hash = Vec::with_capacity(((2 * n) + 5) * 32);
  to_hash.extend(PREFIX);
  to_hash.extend(AGG_0);
  to_hash.extend([0; 32 - PREFIX_AGG_0_LEN]);

  let mut P = Vec::with_capacity(n);
  for member in ring {
    P.push(member[0]);
    to_hash.extend(member[0].compress().to_bytes());
  }

  let mut C = Vec::with_capacity(n);
  for member in ring {
    C.push(member[1] - pseudo_out);
    to_hash.extend(member[1].compress().to_bytes());
  }

  to_hash.extend(I.compress().to_bytes());
  to_hash.extend(D_INV_EIGHT.compress().to_bytes());
  to_hash.extend(pseudo_out.compress().to_bytes());
  // mu_P with agg_0
  let mu_P = hash_to_scalar(&to_hash);
  // mu_C with agg_1
  to_hash[PREFIX_AGG_0_LEN - 1] = b'1';
  let mu_C = hash_to_scalar(&to_hash);

  // Truncate it for the round transcript, altering the DST as needed
  to_hash.truncate(((2 * n) + 1) * 32);
  for i in 0 .. ROUND.len() {
    to_hash[PREFIX.len() + i] = ROUND[i];
  }
  // Unfortunately, it's I D pseudo_out instead of pseudo_out I D, meaning this needs to be
  // truncated just to add it back
  to_hash.extend(pseudo_out.compress().to_bytes());
  to_hash.extend(msg);

  // Configure the loop based on if we're signing or verifying
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
    }

    Mode::Verify(c1) => {
      start = 0;
      end = n;
      c = *c1;
    }
  }

  // Perform the core loop
  let mut c1 = c;
  for i in (start .. end).map(|i| i % n) {
    let c_p = mu_P * c;
    let c_c = mu_C * c;

    // (s_i * G) + (c_p * P_i) + (c_c * C_i)
    let L = match A_c1 {
      Mode::Sign(..) => {
        EdwardsPoint::multiscalar_mul([s[i], c_p, c_c], [ED25519_BASEPOINT_POINT, P[i], C[i]])
      }
      Mode::Verify(..) => {
        BASEPOINT_PRECOMP().vartime_mixed_multiscalar_mul([s[i]], [c_p, c_c], [P[i], C[i]])
      }
    };

    let PH = hash_to_point(&P[i]);

    // (c_p * I) + (c_c * D) + (s_i * PH)
    let R = match A_c1 {
      Mode::Sign(..) => EdwardsPoint::multiscalar_mul([c_p, c_c, s[i]], [I, D, &PH]),
      Mode::Verify(..) => {
        images_precomp.as_ref().unwrap().vartime_mixed_multiscalar_mul([c_p, c_c], [s[i]], [PH])
      }
    };

    to_hash.truncate(((2 * n) + 3) * 32);
    to_hash.extend(L.compress().to_bytes());
    to_hash.extend(R.compress().to_bytes());
    c = hash_to_scalar(&to_hash);

    // This will only execute once and shouldn't need to be constant time. Making it constant time
    // removes the risk of branch prediction creating timing differences depending on ring index
    // however
    c1.conditional_assign(&c, i.ct_eq(&(n - 1)));
  }

  // This first tuple is needed to continue signing, the latter is the c to be tested/worked with
  ((D_INV_EIGHT, c * mu_P, c * mu_C), c1)
}

/// CLSAG signature, as used in Monero.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Clsag {
  pub D: EdwardsPoint,
  pub s: Vec<Scalar>,
  pub c1: Scalar,
}

impl Clsag {
  // Sign core is the extension of core as needed for signing, yet is shared between single signer
  // and multisig, hence why it's still core
  pub(crate) fn sign_core<R: RngCore + CryptoRng>(
    rng: &mut R,
    I: &EdwardsPoint,
    input: &ClsagInput,
    mask: Scalar,
    msg: &[u8; 32],
    A: EdwardsPoint,
    AH: EdwardsPoint,
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
    let ((D, p, c), c1) =
      core(&input.decoys.ring, I, &pseudo_out, msg, &D, &s, &Mode::Sign(r, A, AH));

    (Clsag { D, s, c1 }, pseudo_out, p, c * z)
  }

  /// Generate CLSAG signatures for the given inputs.
  /// inputs is of the form (private key, key image, input).
  /// sum_outputs is for the sum of the outputs' commitment masks.
  pub fn sign<R: RngCore + CryptoRng>(
    rng: &mut R,
    mut inputs: Vec<(Zeroizing<Scalar>, EdwardsPoint, ClsagInput)>,
    sum_outputs: Scalar,
    msg: [u8; 32],
  ) -> Vec<(Clsag, EdwardsPoint)> {
    let mut res = Vec::with_capacity(inputs.len());
    let mut sum_pseudo_outs = Scalar::ZERO;
    for i in 0 .. inputs.len() {
      let mut mask = random_scalar(rng);
      if i == (inputs.len() - 1) {
        mask = sum_outputs - sum_pseudo_outs;
      } else {
        sum_pseudo_outs += mask;
      }

      let mut nonce = Zeroizing::new(random_scalar(rng));
      let (mut clsag, pseudo_out, p, c) = Clsag::sign_core(
        rng,
        &inputs[i].1,
        &inputs[i].2,
        mask,
        &msg,
        nonce.deref() * ED25519_BASEPOINT_TABLE,
        nonce.deref() *
          hash_to_point(&inputs[i].2.decoys.ring[usize::from(inputs[i].2.decoys.i)][0]),
      );
      clsag.s[usize::from(inputs[i].2.decoys.i)] =
        (-((p * inputs[i].0.deref()) + c)) + nonce.deref();
      inputs[i].0.zeroize();
      nonce.zeroize();

      debug_assert!(clsag
        .verify(&inputs[i].2.decoys.ring, &inputs[i].1, &pseudo_out, &msg)
        .is_ok());

      res.push((clsag, pseudo_out));
    }

    res
  }

  /// Verify the CLSAG signature against the given Transaction data.
  pub fn verify(
    &self,
    ring: &[[EdwardsPoint; 2]],
    I: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
    msg: &[u8; 32],
  ) -> Result<(), ClsagError> {
    // Preliminary checks. s, c1, and points must also be encoded canonically, which isn't checked
    // here
    if ring.is_empty() {
      Err(ClsagError::InvalidRing)?;
    }
    if ring.len() != self.s.len() {
      Err(ClsagError::InvalidS)?;
    }
    if I.is_identity() {
      Err(ClsagError::InvalidImage)?;
    }

    let D = self.D.mul_by_cofactor();
    if D.is_identity() {
      Err(ClsagError::InvalidD)?;
    }

    let (_, c1) = core(ring, I, pseudo_out, msg, &D, &self.s, &Mode::Verify(self.c1));
    if c1 != self.c1 {
      Err(ClsagError::InvalidC1)?;
    }
    Ok(())
  }

  pub(crate) fn fee_weight(ring_len: usize) -> usize {
    (ring_len * 32) + 32 + 32
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_raw_vec(write_scalar, &self.s, w)?;
    w.write_all(&self.c1.to_bytes())?;
    write_point(&self.D, w)
  }

  pub fn read<R: Read>(decoys: usize, r: &mut R) -> io::Result<Clsag> {
    Ok(Clsag { s: read_raw_vec(read_scalar, decoys, r)?, c1: read_scalar(r)?, D: read_point(r)? })
  }
}
