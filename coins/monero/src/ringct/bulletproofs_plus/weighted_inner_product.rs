use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use transcript::Transcript;

use multiexp::{multiexp, multiexp_vartime, BatchVerifier};
use group::{
  ff::{Field, PrimeField},
  GroupEncoding,
};
use dalek_ff_group::{Scalar, EdwardsPoint};
use ciphersuite::{Ciphersuite, Ed25519};

use crate::ringct::bulletproofs_plus::{
  ScalarVector, PointVector, GeneratorsList, InnerProductGenerators, padded_pow_of_2,
  weighted_inner_product,
};

// Figure 1
#[derive(Clone, Debug)]
pub struct WipStatement<'a, GB: Clone + AsRef<[EdwardsPoint]>> {
  generators: &'a InnerProductGenerators<'a, GB>,
  P: EdwardsPoint,
  y: ScalarVector,
  inv_y: Option<Vec<Scalar>>,
}

impl<'a, GB: Clone + AsRef<[EdwardsPoint]>> Zeroize for WipStatement<'a, GB> {
  fn zeroize(&mut self) {
    self.P.zeroize();
    self.y.zeroize();
    self.inv_y.zeroize();
  }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct WipWitness {
  a: ScalarVector,
  b: ScalarVector,
  alpha: Scalar,
}

impl WipWitness {
  pub fn new(mut a: ScalarVector, mut b: ScalarVector, alpha: Scalar) -> Self {
    assert!(!a.0.is_empty());
    assert_eq!(a.len(), b.len());

    // Pad to the nearest power of 2
    let missing = padded_pow_of_2(a.len()) - a.len();
    a.0.reserve(missing);
    b.0.reserve(missing);
    for _ in 0 .. missing {
      a.0.push(Scalar::ZERO);
      b.0.push(Scalar::ZERO);
    }

    Self { a, b, alpha }
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct WipProof {
  L: Vec<EdwardsPoint>,
  R: Vec<EdwardsPoint>,
  A: EdwardsPoint,
  B: EdwardsPoint,
  r_answer: Scalar,
  s_answer: Scalar,
  delta_answer: Scalar,
}

impl<'a, GB: 'a + Clone + AsRef<[EdwardsPoint]>> WipStatement<'a, GB> {
  pub fn new(generators: &'a InnerProductGenerators<'a, GB>, P: EdwardsPoint, y: Scalar) -> Self {
    debug_assert_eq!(generators.len(), padded_pow_of_2(generators.len()));

    // y ** n
    let mut y_vec = ScalarVector::new(generators.len());
    y_vec[0] = y;
    for i in 1 .. y_vec.len() {
      y_vec[i] = y_vec[i - 1] * y;
    }

    Self { generators, P, y: y_vec, inv_y: None }
  }

  fn initial_transcript<T: Transcript>(&mut self, transcript: &mut T) {
    transcript.domain_separate(b"weighted_inner_product");
    transcript.append_message(b"P", self.P.to_bytes());
    transcript.append_message(b"y", self.y[0].to_repr());
  }

  fn transcript_L_R<T: Transcript>(transcript: &mut T, L: EdwardsPoint, R: EdwardsPoint) -> Scalar {
    transcript.append_message(b"L", L.to_bytes());
    transcript.append_message(b"R", R.to_bytes());

    let e = Ed25519::hash_to_F(b"weighted_inner_product", transcript.challenge(b"e").as_ref());
    if bool::from(e.is_zero()) {
      panic!("zero challenge in WIP round");
    }
    e
  }

  fn transcript_A_B<T: Transcript>(transcript: &mut T, A: EdwardsPoint, B: EdwardsPoint) -> Scalar {
    transcript.append_message(b"A", A.to_bytes());
    transcript.append_message(b"B", B.to_bytes());

    let e = Ed25519::hash_to_F(b"weighted_inner_product", transcript.challenge(b"e").as_ref());
    if bool::from(e.is_zero()) {
      panic!("zero challenge in final WIP round");
    }
    e
  }

  // Prover's variant of the shared code block to calculate G/H/P when n > 1
  // Returns each permutation of G/H since the prover needs to do operation on each permutation
  // P is dropped as it's unused in the prover's path
  // TODO: It'd still probably be faster to keep in terms of the original generators, both between
  // the reduced amount of group operations and the potential tabling of the generators under
  // multiexp
  fn next_G_H<T: Transcript>(
    transcript: &mut T,
    mut g_bold1: PointVector,
    mut g_bold2: PointVector,
    mut h_bold1: PointVector,
    mut h_bold2: PointVector,
    L: EdwardsPoint,
    R: EdwardsPoint,
    y_inv_n_hat: Scalar,
  ) -> (Scalar, Scalar, Scalar, Scalar, PointVector, PointVector) {
    assert_eq!(g_bold1.len(), g_bold2.len());
    assert_eq!(h_bold1.len(), h_bold2.len());
    assert_eq!(g_bold1.len(), h_bold1.len());

    let e = Self::transcript_L_R(transcript, L, R);
    let inv_e = e.invert().unwrap();

    // This vartime is safe as all of these arguments are public
    let mut new_g_bold = Vec::with_capacity(g_bold1.len());
    let e_y_inv = e * y_inv_n_hat;
    for g_bold in g_bold1.0.drain(..).zip(g_bold2.0.drain(..)) {
      new_g_bold.push(multiexp_vartime(&[(inv_e, g_bold.0), (e_y_inv, g_bold.1)]));
    }

    let mut new_h_bold = Vec::with_capacity(h_bold1.len());
    for h_bold in h_bold1.0.drain(..).zip(h_bold2.0.drain(..)) {
      new_h_bold.push(multiexp_vartime(&[(e, h_bold.0), (inv_e, h_bold.1)]));
    }

    let e_square = e.square();
    let inv_e_square = inv_e.square();

    (e, inv_e, e_square, inv_e_square, PointVector(new_g_bold), PointVector(new_h_bold))
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
  fn challenge_products(challenges: &[(Scalar, Scalar)]) -> Vec<Scalar> {
    let mut products = vec![Scalar::ONE; 1 << challenges.len()];

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

  pub fn prove<R: RngCore + CryptoRng, T: Transcript>(
    mut self,
    rng: &mut R,
    transcript: &mut T,
    witness: WipWitness,
  ) -> WipProof {
    self.initial_transcript(transcript);

    let WipStatement { generators, P, mut y, inv_y } = self;

    assert_eq!(generators.len(), witness.a.len());
    let (g, h) = (generators.g(), generators.h());
    let mut g_bold = vec![];
    let mut h_bold = vec![];
    for i in 0 .. generators.len() {
      g_bold.push(generators.generator(GeneratorsList::GBold1, i));
      h_bold.push(generators.generator(GeneratorsList::HBold1, i));
    }
    let mut g_bold = PointVector(g_bold);
    let mut h_bold = PointVector(h_bold);

    // Check P has the expected relationship
    #[cfg(debug_assertions)]
    {
      let mut P_terms = witness
        .a
        .0
        .iter()
        .copied()
        .zip(g_bold.0.iter().copied())
        .chain(witness.b.0.iter().copied().zip(h_bold.0.iter().copied()))
        .collect::<Vec<_>>();
      P_terms.push((weighted_inner_product(&witness.a, &witness.b, &y), g));
      P_terms.push((witness.alpha, h));
      debug_assert_eq!(multiexp(&P_terms), P);
      P_terms.zeroize();
    }

    let mut a = witness.a.clone();
    let mut b = witness.b.clone();
    let mut alpha = witness.alpha;
    assert_eq!(a.len(), b.len());

    // From here on, g_bold.len() is used as n
    assert_eq!(g_bold.len(), a.len());

    let mut L_vec = vec![];
    let mut R_vec = vec![];

    // else n > 1 case from figure 1
    while g_bold.len() > 1 {
      let (a1, a2) = a.clone().split();
      let (b1, b2) = b.clone().split();
      let (g_bold1, g_bold2) = g_bold.split();
      let (h_bold1, h_bold2) = h_bold.split();

      let n_hat = g_bold1.len();
      assert_eq!(a1.len(), n_hat);
      assert_eq!(a2.len(), n_hat);
      assert_eq!(b1.len(), n_hat);
      assert_eq!(b2.len(), n_hat);
      assert_eq!(g_bold1.len(), n_hat);
      assert_eq!(g_bold2.len(), n_hat);
      assert_eq!(h_bold1.len(), n_hat);
      assert_eq!(h_bold2.len(), n_hat);

      let y_n_hat = y[n_hat - 1];
      y.0.truncate(n_hat);

      let d_l = Scalar::random(&mut *rng);
      let d_r = Scalar::random(&mut *rng);

      let c_l = weighted_inner_product(&a1, &b2, &y);
      let c_r = weighted_inner_product(&(a2.mul(y_n_hat)), &b1, &y);

      // TODO: Calculate these with a batch inversion if inv_y is None
      let y_inv_n_hat =
        inv_y.as_ref().map(|inv_y| inv_y[n_hat - 1]).unwrap_or_else(|| y_n_hat.invert().unwrap());
      debug_assert_eq!(y_inv_n_hat, y_n_hat.invert().unwrap());

      let mut L_terms = a1
        .mul(y_inv_n_hat)
        .0
        .drain(..)
        .zip(g_bold2.0.iter().copied())
        .chain(b2.0.iter().copied().zip(h_bold1.0.iter().copied()))
        .collect::<Vec<_>>();
      L_terms.push((c_l, g));
      L_terms.push((d_l, h));
      let L = multiexp(&L_terms);
      L_vec.push(L);
      L_terms.zeroize();

      let mut R_terms = a2
        .mul(y_n_hat)
        .0
        .drain(..)
        .zip(g_bold1.0.iter().copied())
        .chain(b1.0.iter().copied().zip(h_bold2.0.iter().copied()))
        .collect::<Vec<_>>();
      R_terms.push((c_r, g));
      R_terms.push((d_r, h));
      let R = multiexp(&R_terms);
      R_vec.push(R);
      R_terms.zeroize();

      let (e, inv_e, e_square, inv_e_square);
      (e, inv_e, e_square, inv_e_square, g_bold, h_bold) =
        Self::next_G_H(transcript, g_bold1, g_bold2, h_bold1, h_bold2, L, R, y_inv_n_hat);

      a = a1.mul(e).add_vec(&a2.mul(y_n_hat * inv_e));
      b = b1.mul(inv_e).add_vec(&b2.mul(e));
      alpha += (d_l * e_square) + (d_r * inv_e_square);

      debug_assert_eq!(g_bold.len(), a.len());
      debug_assert_eq!(g_bold.len(), h_bold.len());
      debug_assert_eq!(g_bold.len(), b.len());
    }

    // n == 1 case from figure 1
    assert_eq!(g_bold.len(), 1);
    assert_eq!(h_bold.len(), 1);

    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);

    let r = Scalar::random(&mut *rng);
    let s = Scalar::random(&mut *rng);
    let delta = Scalar::random(&mut *rng);
    let long_n = Scalar::random(&mut *rng);

    let ry = r * y[0];

    let mut A_terms =
      vec![(r, g_bold[0]), (s, h_bold[0]), ((ry * b[0]) + (s * y[0] * a[0]), g), (delta, h)];
    let A = multiexp(&A_terms);
    A_terms.zeroize();

    let mut B_terms = vec![(ry * s, g), (long_n, h)];
    let B = multiexp(&B_terms);
    B_terms.zeroize();

    let e = Self::transcript_A_B(transcript, A, B);

    let r_answer = r + (a[0] * e);
    let s_answer = s + (b[0] * e);
    let delta_answer = long_n + (delta * e) + (alpha * e.square());

    WipProof { L: L_vec, R: R_vec, A, B, r_answer, s_answer, delta_answer }
  }

  pub fn verify<R: RngCore + CryptoRng, T: Transcript>(
    mut self,
    rng: &mut R,
    verifier: &mut BatchVerifier<(), EdwardsPoint>,
    transcript: &mut T,
    proof: WipProof,
  ) {
    self.initial_transcript(transcript);

    let WipStatement { generators, P, y, inv_y } = self;

    let (g, h) = (generators.g(), generators.h());

    // Verify the L/R lengths
    {
      let mut lr_len = 0;
      while (1 << lr_len) < generators.len() {
        lr_len += 1;
      }
      assert_eq!(proof.L.len(), lr_len);
      assert_eq!(proof.R.len(), lr_len);
      assert_eq!(generators.len(), 1 << lr_len);
    }

    let inv_y = inv_y.unwrap_or_else(|| {
      let inv_y = y[0].invert().unwrap();
      let mut res = Vec::with_capacity(y.len());
      res.push(inv_y);
      while res.len() < y.len() {
        res.push(inv_y * res.last().unwrap());
      }
      res
    });

    let mut P_terms = vec![(Scalar::ONE, P)];
    P_terms.reserve(6 + (2 * generators.len()) + proof.L.len());

    let mut challenges = Vec::with_capacity(proof.L.len());
    let product_cache = {
      let mut es = Vec::with_capacity(proof.L.len());
      for (L, R) in proof.L.iter().zip(proof.R.iter()) {
        es.push(Self::transcript_L_R(transcript, *L, *R));
      }

      let mut inv_es = es.clone();
      let mut scratch = vec![Scalar::ZERO; es.len()];
      group::ff::BatchInverter::invert_with_external_scratch(&mut inv_es, &mut scratch);
      drop(scratch);

      assert_eq!(es.len(), inv_es.len());
      assert_eq!(es.len(), proof.L.len());
      assert_eq!(es.len(), proof.R.len());
      for ((e, inv_e), (L, R)) in
        es.drain(..).zip(inv_es.drain(..)).zip(proof.L.iter().zip(proof.R.iter()))
      {
        debug_assert_eq!(e.invert().unwrap(), inv_e);

        challenges.push((e, inv_e));

        let e_square = e.square();
        let inv_e_square = inv_e.square();
        P_terms.push((e_square, *L));
        P_terms.push((inv_e_square, *R));
      }

      Self::challenge_products(&challenges)
    };

    let e = Self::transcript_A_B(transcript, proof.A, proof.B);
    let neg_e_square = -e.square();

    let mut multiexp = P_terms;
    multiexp.reserve(4 + (2 * generators.len()));
    for (scalar, _) in multiexp.iter_mut() {
      *scalar *= neg_e_square;
    }

    let re = proof.r_answer * e;
    for i in 0 .. generators.len() {
      let mut scalar = product_cache[i] * re;
      if i > 0 {
        scalar *= inv_y[i - 1];
      }
      multiexp.push((scalar, generators.generator(GeneratorsList::GBold1, i)));
    }

    let se = proof.s_answer * e;
    for i in 0 .. generators.len() {
      multiexp.push((
        se * product_cache[product_cache.len() - 1 - i],
        generators.generator(GeneratorsList::HBold1, i),
      ));
    }

    multiexp.push((-e, proof.A));
    multiexp.push((proof.r_answer * y[0] * proof.s_answer, g));
    multiexp.push((proof.delta_answer, h));
    multiexp.push((-Scalar::ONE, proof.B));

    verifier.queue(rng, (), multiexp);
  }
}
