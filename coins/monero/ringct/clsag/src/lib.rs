#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

use core::ops::Deref;
use std_shims::{
  vec, vec::Vec,
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

use monero_io::*;
use monero_generators::hash_to_point;
use monero_primitives::{INV_EIGHT, BASEPOINT_PRECOMP, Commitment, Decoys, keccak256_to_scalar};

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use multisig::{ClsagMultisigMaskSender, ClsagAddendum, ClsagMultisig};

#[cfg(all(feature = "std", test))]
mod tests;

/// Errors when working with CLSAGs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum ClsagError {
  /// The ring was invalid (such as being too small or too large).
  #[cfg_attr(feature = "std", error("invalid ring"))]
  InvalidRing,
  /// The discrete logarithm of the key, scaling G, wasn't equivalent to the signing ring member.
  #[cfg_attr(feature = "std", error("invalid commitment"))]
  InvalidKey,
  /// The commitment opening provided did not match the ring member's.
  #[cfg_attr(feature = "std", error("invalid commitment"))]
  InvalidCommitment,
  /// The key image was invalid (such as being identity or torsioned)
  #[cfg_attr(feature = "std", error("invalid key image"))]
  InvalidImage,
  /// The `D` component was invalid.
  #[cfg_attr(feature = "std", error("invalid D"))]
  InvalidD,
  /// The `s` vector was invalid.
  #[cfg_attr(feature = "std", error("invalid s"))]
  InvalidS,
  /// The `c1` variable was invalid.
  #[cfg_attr(feature = "std", error("invalid c1"))]
  InvalidC1,
}

/// Context on the input being signed for.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ClsagContext {
  // The opening for the commitment of the signing ring member
  commitment: Commitment,
  // Selected ring members' positions, signer index, and ring
  decoys: Decoys,
}

impl ClsagContext {
  /// Create a new context, as necessary for signing.
  pub fn new(decoys: Decoys, commitment: Commitment) -> Result<ClsagContext, ClsagError> {
    if decoys.len() > u8::MAX.into() {
      Err(ClsagError::InvalidRing)?;
    }

    // Validate the commitment matches
    if decoys.signer_ring_members()[1] != commitment.calculate() {
      Err(ClsagError::InvalidCommitment)?;
    }

    Ok(ClsagContext { commitment, decoys })
  }
}

#[allow(clippy::large_enum_variant)]
enum Mode {
  Sign(usize, EdwardsPoint, EdwardsPoint),
  Verify(Scalar),
}

// Core of the CLSAG algorithm, applicable to both sign and verify with minimal differences
//
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
  let mu_P = keccak256_to_scalar(&to_hash);
  // mu_C with agg_1
  to_hash[PREFIX_AGG_0_LEN - 1] = b'1';
  let mu_C = keccak256_to_scalar(&to_hash);

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
      c = keccak256_to_scalar(&to_hash);
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

    let PH = hash_to_point(P[i].compress().0);

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
    c = keccak256_to_scalar(&to_hash);

    // This will only execute once and shouldn't need to be constant time. Making it constant time
    // removes the risk of branch prediction creating timing differences depending on ring index
    // however
    c1.conditional_assign(&c, i.ct_eq(&(n - 1)));
  }

  // This first tuple is needed to continue signing, the latter is the c to be tested/worked with
  ((D_INV_EIGHT, c * mu_P, c * mu_C), c1)
}

/// The CLSAG signature, as used in Monero.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Clsag {
  D: EdwardsPoint,
  s: Vec<Scalar>,
  c1: Scalar,
}

struct ClsagSignCore {
  incomplete_clsag: Clsag,
  pseudo_out: EdwardsPoint,
  key_challenge: Scalar,
  challenged_mask: Scalar,
}

impl Clsag {
  // Sign core is the extension of core as needed for signing, yet is shared between single signer
  // and multisig, hence why it's still core
  fn sign_core<R: RngCore + CryptoRng>(
    rng: &mut R,
    I: &EdwardsPoint,
    input: &ClsagContext,
    mask: Scalar,
    msg: &[u8; 32],
    A: EdwardsPoint,
    AH: EdwardsPoint,
  ) -> ClsagSignCore {
    let r: usize = input.decoys.signer_index().into();

    let pseudo_out = Commitment::new(mask, input.commitment.amount).calculate();
    let mask_delta = input.commitment.mask - mask;

    let H = hash_to_point(input.decoys.ring()[r][0].compress().0);
    let D = H * mask_delta;
    let mut s = Vec::with_capacity(input.decoys.ring().len());
    for _ in 0 .. input.decoys.ring().len() {
      s.push(Scalar::random(rng));
    }
    let ((D, c_p, c_c), c1) =
      core(input.decoys.ring(), I, &pseudo_out, msg, &D, &s, &Mode::Sign(r, A, AH));

    ClsagSignCore {
      incomplete_clsag: Clsag { D, s, c1 },
      pseudo_out,
      key_challenge: c_p,
      challenged_mask: c_c * mask_delta,
    }
  }

  /// Sign CLSAG signatures for the provided inputs.
  ///
  /// Monero ensures the rerandomized input commitments have the same value as the outputs by
  /// checking `sum(rerandomized_input_commitments) - sum(output_commitments) == 0`. This requires
  /// not only the amounts balance, yet also
  /// `sum(input_commitment_masks) - sum(output_commitment_masks)`.
  ///
  /// Monero solves this by following the wallet protocol to determine each output commitment's
  /// randomness, then using random masks for all but the last input. The last input is
  /// rerandomized to the necessary mask for the equation to balance.
  ///
  /// Due to Monero having this behavior, it only makes sense to sign CLSAGs as a list, hence this
  /// API being the way it is.
  ///
  /// `inputs` is of the form (discrete logarithm of the key, context).
  ///
  /// `sum_outputs` is for the sum of the output commitments' masks.
  pub fn sign<R: RngCore + CryptoRng>(
    rng: &mut R,
    mut inputs: Vec<(Zeroizing<Scalar>, ClsagContext)>,
    sum_outputs: Scalar,
    msg: [u8; 32],
  ) -> Result<Vec<(Clsag, EdwardsPoint)>, ClsagError> {
    // Create the key images
    let mut key_image_generators = vec![];
    let mut key_images = vec![];
    for input in &inputs {
      let key = input.1.decoys.signer_ring_members()[0];

      // Check the key is consistent
      if (ED25519_BASEPOINT_TABLE * input.0.deref()) != key {
        Err(ClsagError::InvalidKey)?;
      }

      let key_image_generator = hash_to_point(key.compress().0);
      key_image_generators.push(key_image_generator);
      key_images.push(key_image_generator * input.0.deref());
    }

    let mut res = Vec::with_capacity(inputs.len());
    let mut sum_pseudo_outs = Scalar::ZERO;
    for i in 0 .. inputs.len() {
      let mask;
      // If this is the last input, set the mask as described above
      if i == (inputs.len() - 1) {
        mask = sum_outputs - sum_pseudo_outs;
      } else {
        mask = Scalar::random(rng);
        sum_pseudo_outs += mask;
      }

      let mut nonce = Zeroizing::new(Scalar::random(rng));
      let ClsagSignCore { mut incomplete_clsag, pseudo_out, key_challenge, challenged_mask } =
        Clsag::sign_core(
          rng,
          &key_images[i],
          &inputs[i].1,
          mask,
          &msg,
          nonce.deref() * ED25519_BASEPOINT_TABLE,
          nonce.deref() * key_image_generators[i],
        );
      // Effectively r - c x, except c x is (c_p x) + (c_c z), where z is the delta between the
      // ring member's commitment and our pseudo-out commitment (which will only have a known
      // discrete log over G if the amounts cancel out)
      incomplete_clsag.s[usize::from(inputs[i].1.decoys.signer_index())] =
        nonce.deref() - ((key_challenge * inputs[i].0.deref()) + challenged_mask);
      let clsag = incomplete_clsag;

      // Zeroize private keys and nonces.
      inputs[i].0.zeroize();
      nonce.zeroize();

      debug_assert!(clsag
        .verify(inputs[i].1.decoys.ring(), &key_images[i], &pseudo_out, &msg)
        .is_ok());

      res.push((clsag, pseudo_out));
    }

    Ok(res)
  }

  /// Verify a CLSAG signature for the provided context.
  pub fn verify(
    &self,
    ring: &[[EdwardsPoint; 2]],
    I: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
    msg: &[u8; 32],
  ) -> Result<(), ClsagError> {
    // Preliminary checks
    // s, c1, and points must also be encoded canonically, which is checked at time of decode
    if ring.is_empty() {
      Err(ClsagError::InvalidRing)?;
    }
    if ring.len() != self.s.len() {
      Err(ClsagError::InvalidS)?;
    }
    if I.is_identity() || (!I.is_torsion_free()) {
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

  /// The weight a CLSAG will take within a Monero transaction.
  pub fn fee_weight(ring_len: usize) -> usize {
    (ring_len * 32) + 32 + 32
  }

  /// Write a CLSAG.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_raw_vec(write_scalar, &self.s, w)?;
    w.write_all(&self.c1.to_bytes())?;
    write_point(&self.D, w)
  }

  /// Read a CLSAG.
  pub fn read<R: Read>(decoys: usize, r: &mut R) -> io::Result<Clsag> {
    Ok(Clsag { s: read_raw_vec(read_scalar, decoys, r)?, c1: read_scalar(r)?, D: read_point(r)? })
  }
}
