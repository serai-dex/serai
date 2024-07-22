use multiexp::multiexp_vartime;
use ciphersuite::{group::ff::Field, Ciphersuite};

#[rustfmt::skip]
use crate::{ScalarVector, PointVector, ProofGenerators, BatchVerifier, transcript::*, padded_pow_of_2};

/// An error from proving/verifying Inner-Product statements.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpError {
  /// An incorrect amount of generators was provided.
  IncorrectAmountOfGenerators,
  /// The witness was inconsistent to the statement.
  ///
  /// Sanity checks on the witness are always performed. If the library is compiled with debug
  /// assertions on, whether or not this witness actually opens `P` is checked.
  InconsistentWitness,
  /// The proof wasn't complete and the necessary values could not be read from the transcript.
  IncompleteProof,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum P<C: Ciphersuite> {
  Verifier { verifier_weight: C::F },
  Prover(C::G),
}

/// The Bulletproofs Inner-Product statement.
///
/// This is for usage with Protocol 2 from the Bulletproofs paper.
#[derive(Clone, Debug)]
pub(crate) struct IpStatement<'a, C: Ciphersuite> {
  generators: ProofGenerators<'a, C>,
  // Weights for h_bold
  h_bold_weights: ScalarVector<C::F>,
  // u as the discrete logarithm of G
  u: C::F,
  // P
  P: P<C>,
}

/// The witness for the Bulletproofs Inner-Product statement.
#[derive(Clone, Debug)]
pub(crate) struct IpWitness<C: Ciphersuite> {
  // a
  a: ScalarVector<C::F>,
  // b
  b: ScalarVector<C::F>,
}

impl<C: Ciphersuite> IpWitness<C> {
  /// Construct a new witness for an Inner-Product statement.
  ///
  /// If the witness is less than a power of two, it is padded to the nearest power of two.
  ///
  /// This functions return None if the lengths of a, b are mismatched or either are empty.
  pub(crate) fn new(mut a: ScalarVector<C::F>, mut b: ScalarVector<C::F>) -> Option<Self> {
    if a.0.is_empty() || (a.len() != b.len()) {
      None?;
    }

    // Pad to the nearest power of 2
    let missing = padded_pow_of_2(a.len()) - a.len();
    a.0.reserve(missing);
    b.0.reserve(missing);
    for _ in 0 .. missing {
      a.0.push(C::F::ZERO);
      b.0.push(C::F::ZERO);
    }

    Some(Self { a, b })
  }
}

impl<'a, C: Ciphersuite> IpStatement<'a, C> {
  /// Create a new Inner-Product statement.
  ///
  /// This does not perform any transcripting of any variables within this statement. They must be
  /// deterministic to the existing transcript.
  pub(crate) fn new(
    generators: ProofGenerators<'a, C>,
    h_bold_weights: ScalarVector<C::F>,
    u: C::F,
    P: P<C>,
  ) -> Result<Self, IpError> {
    if generators.h_bold_slice().len() != h_bold_weights.len() {
      Err(IpError::IncorrectAmountOfGenerators)?
    }
    Ok(Self { generators, h_bold_weights, u, P })
  }

  /// Prove for this Inner-Product statement.
  ///
  /// Returns an error if this statement couldn't be proven for (such as if the witness isn't
  /// consistent).
  pub(crate) fn prove(
    self,
    transcript: &mut Transcript,
    witness: IpWitness<C>,
  ) -> Result<(), IpError> {
    let (mut g_bold, mut h_bold, u, mut P, mut a, mut b) = {
      let IpStatement { generators, h_bold_weights, u, P } = self;
      let u = generators.g() * u;

      // Ensure we have the exact amount of generators
      if generators.g_bold_slice().len() != witness.a.len() {
        Err(IpError::IncorrectAmountOfGenerators)?;
      }
      // Acquire a local copy of the generators
      let g_bold = PointVector::<C>(generators.g_bold_slice().to_vec());
      let h_bold = PointVector::<C>(generators.h_bold_slice().to_vec()).mul_vec(&h_bold_weights);

      let IpWitness { a, b } = witness;

      let P = match P {
        P::Prover(point) => point,
        P::Verifier { .. } => {
          panic!("prove called with a P specification which was for the verifier")
        }
      };

      // Ensure this witness actually opens this statement
      #[cfg(debug_assertions)]
      {
        let ag = a.0.iter().cloned().zip(g_bold.0.iter().cloned());
        let bh = b.0.iter().cloned().zip(h_bold.0.iter().cloned());
        let cu = core::iter::once((a.inner_product(b.0.iter()), u));
        if P != multiexp_vartime(&ag.chain(bh).chain(cu).collect::<Vec<_>>()) {
          Err(IpError::InconsistentWitness)?;
        }
      }

      (g_bold, h_bold, u, P, a, b)
    };

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
      let cl = a1.inner_product(b2.0.iter());
      let cr = a2.inner_product(b1.0.iter());

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

      // Now that we've calculate L, R, transcript them to receive x (26-27)
      transcript.push_point(L);
      transcript.push_point(R);
      let x: C::F = transcript.challenge();
      let x_inv = x.invert().unwrap();

      // The prover and verifier now calculate the following (28-31)
      g_bold = PointVector(Vec::with_capacity(g_bold1.len()));
      for (a, b) in g_bold1.0.into_iter().zip(g_bold2.0.into_iter()) {
        g_bold.0.push(multiexp_vartime(&[(x_inv, a), (x, b)]));
      }
      h_bold = PointVector(Vec::with_capacity(h_bold1.len()));
      for (a, b) in h_bold1.0.into_iter().zip(h_bold2.0.into_iter()) {
        h_bold.0.push(multiexp_vartime(&[(x, a), (x_inv, b)]));
      }
      P = (L * (x * x)) + P + (R * (x_inv * x_inv));

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
    transcript.push_scalar(a[0]);
    transcript.push_scalar(b[0]);
    Ok(())
  }

  /*
  This has room for optimization worth investigating further. It currently takes
  an iterative approach. It can be optimized further via divide and conquer.

  Assume there are 4 challenges.

  Iterative approach (current):
    1. Do the optimal multiplications across challenge column 0 and 1.
    2. Do the optimal multiplications across that result and column 2.
    3. Do the optimal multiplications across that result and column 3.

  Divide and conquer (worth investigating further):
    1. Do the optimal multiplications across challenge column 0 and 1.
    2. Do the optimal multiplications across challenge column 2 and 3.
    3. Multiply both results together.

  When there are 4 challenges (n=16), the iterative approach does 28 multiplications
  versus divide and conquer's 24.
  */
  fn challenge_products(challenges: &[(C::F, C::F)]) -> Vec<C::F> {
    let mut products = vec![C::F::ONE; 1 << challenges.len()];

    if !challenges.is_empty() {
      products[0] = challenges[0].1;
      products[1] = challenges[0].0;

      for (j, challenge) in challenges.iter().enumerate().skip(1) {
        let mut slots = (1 << (j + 1)) - 1;
        while slots > 0 {
          products[slots] = products[slots / 2] * challenge.0;
          products[slots - 1] = products[slots / 2] * challenge.1;

          slots = slots.saturating_sub(2);
        }
      }

      // Sanity check since if the above failed to populate, it'd be critical
      for product in &products {
        debug_assert!(!bool::from(product.is_zero()));
      }
    }

    products
  }

  /// Queue an Inner-Product proof for batch verification.
  ///
  /// This will return Err if there is an error. This will return Ok if the proof was successfully
  /// queued for batch verification. The caller is required to verify the batch in order to ensure
  /// the proof is actually correct.
  pub(crate) fn verify(
    self,
    verifier: &mut BatchVerifier<C>,
    transcript: &mut VerifierTranscript,
  ) -> Result<(), IpError> {
    let IpStatement { generators, h_bold_weights, u, P } = self;

    // Calculate the discrete log w.r.t. 2 for the amount of generators present
    let mut lr_len = 0;
    while (1 << lr_len) < generators.g_bold_slice().len() {
      lr_len += 1;
    }

    let weight = match P {
      P::Prover(_) => panic!("prove called with a P specification which was for the prover"),
      P::Verifier { verifier_weight } => verifier_weight,
    };

    // Again, we start with the `else: (n > 1)` case

    // We need x, x_inv per lines 25-27 for lines 28-31
    let mut L = Vec::with_capacity(lr_len);
    let mut R = Vec::with_capacity(lr_len);
    let mut xs: Vec<C::F> = Vec::with_capacity(lr_len);
    for _ in 0 .. lr_len {
      L.push(transcript.read_point::<C>().map_err(|_| IpError::IncompleteProof)?);
      R.push(transcript.read_point::<C>().map_err(|_| IpError::IncompleteProof)?);
      xs.push(transcript.challenge());
    }

    // We calculate their inverse in batch
    let mut x_invs = xs.clone();
    {
      let mut scratch = vec![C::F::ZERO; x_invs.len()];
      ciphersuite::group::ff::BatchInverter::invert_with_external_scratch(
        &mut x_invs,
        &mut scratch,
      );
    }

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
      let mut challenges = Vec::with_capacity(lr_len);

      let x_iter = xs.into_iter().zip(x_invs);
      let lr_iter = L.into_iter().zip(R);
      for ((x, x_inv), (L, R)) in x_iter.zip(lr_iter) {
        challenges.push((x, x_inv));
        verifier.additional.push((weight * x.square(), L));
        verifier.additional.push((weight * x_inv.square(), R));
      }

      Self::challenge_products(&challenges)
    };

    // And now for the `if n = 1` case
    let a = transcript.read_scalar::<C>().map_err(|_| IpError::IncompleteProof)?;
    let b = transcript.read_scalar::<C>().map_err(|_| IpError::IncompleteProof)?;
    let c = a * b;

    // The multiexp of these terms equate to the final permutation of P
    // We now add terms for a * g_bold' + b * h_bold' b + c * u, with the scalars negative such
    // that the terms sum to 0 for an honest prover

    // The g_bold * a term case from line 16
    #[allow(clippy::needless_range_loop)]
    for i in 0 .. generators.g_bold_slice().len() {
      verifier.g_bold[i] -= weight * product_cache[i] * a;
    }
    // The h_bold * b term case from line 16
    for i in 0 .. generators.h_bold_slice().len() {
      verifier.h_bold[i] -=
        weight * product_cache[product_cache.len() - 1 - i] * b * h_bold_weights[i];
    }
    // The c * u term case from line 16
    verifier.g -= weight * c * u;

    Ok(())
  }
}
