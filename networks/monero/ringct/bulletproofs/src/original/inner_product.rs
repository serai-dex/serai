use std_shims::{vec, vec::Vec};

use zeroize::Zeroize;

use curve25519_dalek::{Scalar, EdwardsPoint};

use monero_generators::H;
use monero_primitives::{INV_EIGHT, keccak256_to_scalar};
use crate::{
  core::{multiexp_vartime, challenge_products},
  scalar_vector::ScalarVector,
  point_vector::PointVector,
  BulletproofsBatchVerifier,
};

/// An error from proving/verifying Inner-Product statements.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IpError {
  IncorrectAmountOfGenerators,
  DifferingLrLengths,
}

/// The Bulletproofs Inner-Product statement.
///
/// This is for usage with Protocol 2 from the Bulletproofs paper.
#[derive(Clone, Debug)]
pub(crate) struct IpStatement {
  // Weights for h_bold
  h_bold_weights: ScalarVector,
  // u as the discrete logarithm of G
  u: Scalar,
}

/// The witness for the Bulletproofs Inner-Product statement.
#[derive(Clone, Debug)]
pub(crate) struct IpWitness {
  // a
  a: ScalarVector,
  // b
  b: ScalarVector,
}

impl IpWitness {
  /// Construct a new witness for an Inner-Product statement.
  ///
  /// This functions return None if the lengths of a, b are mismatched, not a power of two, or are
  /// empty.
  pub(crate) fn new(a: ScalarVector, b: ScalarVector) -> Option<Self> {
    if a.0.is_empty() || (a.len() != b.len()) {
      None?;
    }

    let mut power_of_2 = 1;
    while power_of_2 < a.len() {
      power_of_2 <<= 1;
    }
    if power_of_2 != a.len() {
      None?;
    }

    Some(Self { a, b })
  }
}

/// A proof for the Bulletproofs Inner-Product statement.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct IpProof {
  pub(crate) L: Vec<EdwardsPoint>,
  pub(crate) R: Vec<EdwardsPoint>,
  pub(crate) a: Scalar,
  pub(crate) b: Scalar,
}

impl IpStatement {
  /// Create a new Inner-Product statement which won't transcript P.
  ///
  /// This MUST only be called when P is deterministic to already transcripted elements.
  pub(crate) fn new_without_P_transcript(h_bold_weights: ScalarVector, u: Scalar) -> Self {
    Self { h_bold_weights, u }
  }

  // Transcript a round of the protocol
  fn transcript_L_R(transcript: Scalar, L: EdwardsPoint, R: EdwardsPoint) -> Scalar {
    let mut transcript = transcript.to_bytes().to_vec();
    transcript.extend(L.compress().to_bytes());
    transcript.extend(R.compress().to_bytes());
    keccak256_to_scalar(transcript)
  }

  /// Prove for this Inner-Product statement.
  ///
  /// Returns an error if this statement couldn't be proven for (such as if the witness isn't
  /// consistent).
  pub(crate) fn prove(
    self,
    mut transcript: Scalar,
    witness: IpWitness,
  ) -> Result<IpProof, IpError> {
    let generators = &crate::original::GENERATORS;
    let g_bold_slice = &generators.G[.. witness.a.len()];
    let h_bold_slice = &generators.H[.. witness.a.len()];

    let (mut g_bold, mut h_bold, u, mut a, mut b) = {
      let IpStatement { h_bold_weights, u } = self;
      let u = *H * u;

      // Ensure we have the exact amount of weights
      if h_bold_weights.len() != g_bold_slice.len() {
        Err(IpError::IncorrectAmountOfGenerators)?;
      }
      // Acquire a local copy of the generators
      let g_bold = PointVector(g_bold_slice.to_vec());
      let h_bold = PointVector(h_bold_slice.to_vec()).mul_vec(&h_bold_weights);

      let IpWitness { a, b } = witness;

      (g_bold, h_bold, u, a, b)
    };

    let mut L_vec = vec![];
    let mut R_vec = vec![];

    // `else: (n > 1)` case, lines 18-35 of the Bulletproofs paper
    // This interprets `g_bold.len()` as `n`
    while g_bold.len() > 1 {
      // Split a, b, g_bold, h_bold as needed for lines 20-24
      let (a1, a2) = a.clone().split();
      let (b1, b2) = b.clone().split();

      let (g_bold1, g_bold2) = g_bold.split();
      let (h_bold1, h_bold2) = h_bold.split();

      let n_hat = g_bold1.len();

      // Sanity
      debug_assert_eq!(a1.len(), n_hat);
      debug_assert_eq!(a2.len(), n_hat);
      debug_assert_eq!(b1.len(), n_hat);
      debug_assert_eq!(b2.len(), n_hat);
      debug_assert_eq!(g_bold1.len(), n_hat);
      debug_assert_eq!(g_bold2.len(), n_hat);
      debug_assert_eq!(h_bold1.len(), n_hat);
      debug_assert_eq!(h_bold2.len(), n_hat);

      // cl, cr, lines 21-22
      let cl = a1.clone().inner_product(&b2);
      let cr = a2.clone().inner_product(&b1);

      let L = {
        let mut L_terms = Vec::with_capacity(1 + (2 * g_bold1.len()));
        for (a, g) in a1.0.iter().zip(g_bold2.0.iter()) {
          L_terms.push((*a, *g));
        }
        for (b, h) in b2.0.iter().zip(h_bold1.0.iter()) {
          L_terms.push((*b, *h));
        }
        L_terms.push((cl, u));
        // Uses vartime since this isn't a ZK proof
        multiexp_vartime(&L_terms)
      };
      L_vec.push(L * INV_EIGHT());

      let R = {
        let mut R_terms = Vec::with_capacity(1 + (2 * g_bold1.len()));
        for (a, g) in a2.0.iter().zip(g_bold1.0.iter()) {
          R_terms.push((*a, *g));
        }
        for (b, h) in b1.0.iter().zip(h_bold2.0.iter()) {
          R_terms.push((*b, *h));
        }
        R_terms.push((cr, u));
        multiexp_vartime(&R_terms)
      };
      R_vec.push(R * INV_EIGHT());

      // Now that we've calculate L, R, transcript them to receive x (26-27)
      transcript = Self::transcript_L_R(transcript, *L_vec.last().unwrap(), *R_vec.last().unwrap());
      let x = transcript;
      let x_inv = x.invert();

      // The prover and verifier now calculate the following (28-31)
      g_bold = PointVector(Vec::with_capacity(g_bold1.len()));
      for (a, b) in g_bold1.0.into_iter().zip(g_bold2.0.into_iter()) {
        g_bold.0.push(multiexp_vartime(&[(x_inv, a), (x, b)]));
      }
      h_bold = PointVector(Vec::with_capacity(h_bold1.len()));
      for (a, b) in h_bold1.0.into_iter().zip(h_bold2.0.into_iter()) {
        h_bold.0.push(multiexp_vartime(&[(x, a), (x_inv, b)]));
      }

      // 32-34
      a = (a1 * x) + &(a2 * x_inv);
      b = (b1 * x_inv) + &(b2 * x);
    }

    // `if n = 1` case from line 14-17

    // Sanity
    debug_assert_eq!(g_bold.len(), 1);
    debug_assert_eq!(h_bold.len(), 1);
    debug_assert_eq!(a.len(), 1);
    debug_assert_eq!(b.len(), 1);

    // We simply send a/b
    Ok(IpProof { L: L_vec, R: R_vec, a: a[0], b: b[0] })
  }

  /// Queue an Inner-Product proof for batch verification.
  ///
  /// This will return Err if there is an error. This will return Ok if the proof was successfully
  /// queued for batch verification. The caller is required to verify the batch in order to ensure
  /// the proof is actually correct.
  pub(crate) fn verify(
    self,
    verifier: &mut BulletproofsBatchVerifier,
    ip_rows: usize,
    mut transcript: Scalar,
    verifier_weight: Scalar,
    proof: IpProof,
  ) -> Result<(), IpError> {
    let generators = &crate::original::GENERATORS;
    let g_bold_slice = &generators.G[.. ip_rows];
    let h_bold_slice = &generators.H[.. ip_rows];

    let IpStatement { h_bold_weights, u } = self;

    // Verify the L/R lengths
    {
      // Calculate the discrete log w.r.t. 2 for the amount of generators present
      let mut lr_len = 0;
      while (1 << lr_len) < g_bold_slice.len() {
        lr_len += 1;
      }

      // This proof has less/more terms than the passed in generators are for
      if proof.L.len() != lr_len {
        Err(IpError::IncorrectAmountOfGenerators)?;
      }
      if proof.L.len() != proof.R.len() {
        Err(IpError::DifferingLrLengths)?;
      }
    }

    // Again, we start with the `else: (n > 1)` case

    // We need x, x_inv per lines 25-27 for lines 28-31
    let mut xs = Vec::with_capacity(proof.L.len());
    for (L, R) in proof.L.iter().zip(proof.R.iter()) {
      transcript = Self::transcript_L_R(transcript, *L, *R);
      xs.push(transcript);
    }

    // We calculate their inverse in batch
    let mut x_invs = xs.clone();
    Scalar::batch_invert(&mut x_invs);

    // Now, with x and x_inv, we need to calculate g_bold', h_bold', P'
    //
    // For the sake of performance, we solely want to calculate all of these in terms of scalings
    // for g_bold, h_bold, P, and don't want to actually perform intermediary scalings of the
    // points
    //
    // L and R are easy, as it's simply x**2, x**-2
    //
    // For the series of g_bold, h_bold, we use the `challenge_products` function
    // For how that works, please see its own documentation
    let product_cache = {
      let mut challenges = Vec::with_capacity(proof.L.len());

      let x_iter = xs.into_iter().zip(x_invs);
      let lr_iter = proof.L.into_iter().zip(proof.R);
      for ((x, x_inv), (L, R)) in x_iter.zip(lr_iter) {
        challenges.push((x, x_inv));
        verifier.0.other.push((verifier_weight * (x * x), L.mul_by_cofactor()));
        verifier.0.other.push((verifier_weight * (x_inv * x_inv), R.mul_by_cofactor()));
      }

      challenge_products(&challenges)
    };

    // And now for the `if n = 1` case
    let c = proof.a * proof.b;

    // The multiexp of these terms equate to the final permutation of P
    // We now add terms for a * g_bold' + b * h_bold' b + c * u, with the scalars negative such
    // that the terms sum to 0 for an honest prover

    // The g_bold * a term case from line 16
    #[allow(clippy::needless_range_loop)]
    for i in 0 .. g_bold_slice.len() {
      verifier.0.g_bold[i] -= verifier_weight * product_cache[i] * proof.a;
    }
    // The h_bold * b term case from line 16
    for i in 0 .. h_bold_slice.len() {
      verifier.0.h_bold[i] -=
        verifier_weight * product_cache[product_cache.len() - 1 - i] * proof.b * h_bold_weights[i];
    }
    // The c * u term case from line 16
    verifier.0.h -= verifier_weight * c * u;

    Ok(())
  }
}
