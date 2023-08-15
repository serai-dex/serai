use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use transcript::Transcript;

use multiexp::{multiexp, Point as MultiexpPoint, BatchVerifier};
use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite,
};

use crate::{
  ScalarVector, ScalarMatrix, PointVector, GeneratorsList, ProofGenerators, padded_pow_of_2,
  weighted_inner_product::{WipStatement, WipWitness, WipProof},
};

// Figure 4
#[derive(Clone, Debug)]
pub struct ArithmeticCircuitStatement<'a, T: 'static + Transcript, C: Ciphersuite> {
  generators: ProofGenerators<'a, T, C>,
  V: PointVector<C>,
  WL: ScalarMatrix<C>,
  WR: ScalarMatrix<C>,
  WO: ScalarMatrix<C>,
  WV: ScalarMatrix<C>,
  c: ScalarVector<C>,
}

impl<'a, T: 'static + Transcript, C: Ciphersuite> Zeroize for ArithmeticCircuitStatement<'a, T, C> {
  fn zeroize(&mut self) {
    self.V.zeroize();
    self.WL.zeroize();
    self.WR.zeroize();
    self.WO.zeroize();
    self.WV.zeroize();
    self.c.zeroize();
  }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ArithmeticCircuitWitness<C: Ciphersuite> {
  pub(crate) aL: ScalarVector<C>,
  pub(crate) aR: ScalarVector<C>,
  pub(crate) aO: ScalarVector<C>,
  pub(crate) v: ScalarVector<C>,
  gamma: ScalarVector<C>,
}

impl<C: Ciphersuite> ArithmeticCircuitWitness<C> {
  pub fn new(
    aL: ScalarVector<C>,
    aR: ScalarVector<C>,
    v: ScalarVector<C>,
    gamma: ScalarVector<C>,
  ) -> Self {
    assert_eq!(aL.len(), aR.len());
    assert_eq!(v.len(), gamma.len());

    let aO = aL.mul_vec(&aR);
    ArithmeticCircuitWitness { aL, aR, aO, v, gamma }
  }
}

#[derive(Clone, Debug, Zeroize)]
pub struct ArithmeticCircuitProof<C: Ciphersuite> {
  pub(crate) A: C::G,
  wip: WipProof<C>,
}

impl<'a, T: 'static + Transcript, C: Ciphersuite> ArithmeticCircuitStatement<'a, T, C> {
  /// Create a new ArithmeticCircuitStatement for the specified relationship.
  ///
  /// The weights and c vector are not transcripted. They're expected to be deterministic from the
  /// static program and higher-level statement. If your constraints are variable with regards to
  /// variables which aren't the commitments, transcript as needed before calling prove/verify.
  pub fn new(
    generators: ProofGenerators<'a, T, C>,
    V: PointVector<C>,
    WL: ScalarMatrix<C>,
    WR: ScalarMatrix<C>,
    WO: ScalarMatrix<C>,
    WV: ScalarMatrix<C>,
    c: ScalarVector<C>,
  ) -> Self {
    let m = V.len();

    // Determine q/n by WL length/width
    let q = WL.length();
    let n = WL.width();

    assert_eq!(WR.length(), q);
    assert_eq!(WR.width(), n);
    assert_eq!(WO.length(), q);
    assert_eq!(WO.width(), n);
    assert_eq!(WV.length(), q);
    assert_eq!(WV.width(), m);

    assert_eq!(c.len(), q);

    Self { generators, V, WL, WR, WO, WV, c }
  }

  fn initial_transcript(&self, transcript: &mut T) {
    transcript.domain_separate(b"arithmetic_circuit_proof");
    self.V.transcript(transcript, b"commitment");
  }

  fn transcript_A(transcript: &mut T, A: C::G) -> (C::F, C::F) {
    transcript.append_message(b"A", A.to_bytes());

    let y = C::hash_to_F(b"arithmetic_circuit_proof", transcript.challenge(b"y").as_ref());
    if bool::from(y.is_zero()) {
      panic!("zero challenge in arithmetic circuit proof");
    }

    let z = C::hash_to_F(b"arithmetic_circuit_proof", transcript.challenge(b"z").as_ref());
    if bool::from(z.is_zero()) {
      panic!("zero challenge in arithmetic circuit proof");
    }

    (y, z)
  }

  fn compute_A_hat(
    &self,
    transcript: &mut T,
    A: C::G,
  ) -> (
    ScalarVector<C>,
    Vec<C::F>,
    ScalarVector<C>,
    ScalarVector<C>,
    ScalarVector<C>,
    ScalarVector<C>,
    Vec<(C::F, MultiexpPoint<C::G>)>,
  ) {
    // TODO: First perform the WIP transcript before acquiring challenges
    let (y, z) = Self::transcript_A(transcript, A);

    let q = self.c.len();
    let n = self.WL.width();
    assert!(n != 0);

    let z2 = z * z;
    let mut z_q = Vec::with_capacity(q);
    z_q.push(z);
    while z_q.len() < q {
      z_q.push(*z_q.last().unwrap() * z2);
    }
    let z_q = ScalarVector(z_q);

    let n = padded_pow_of_2(n);
    let mut y_n = Vec::with_capacity(n);
    y_n.push(y);
    let mut inv_y_n = Vec::with_capacity(n);
    inv_y_n.push(y.invert().unwrap());
    while y_n.len() < n {
      y_n.push(y_n[y_n.len() - 1] * y);
      inv_y_n.push(inv_y_n[inv_y_n.len() - 1] * inv_y_n[0]);
    }
    let inv_y_n = ScalarVector::<C>(inv_y_n);

    let t_y_z = |W: &ScalarMatrix<C>| {
      ScalarVector(W.mul_vec(&z_q).0.drain(..).enumerate().map(|(i, w)| w * inv_y_n[i]).collect())
    };
    let WL_y_z = t_y_z(&self.WL);
    let WR_y_z = t_y_z(&self.WR);
    let WO_y_z = t_y_z(&self.WO);

    let z_q_WV = self.WV.mul_vec(&z_q);
    // This line ensures we didn't have too many commitments specified
    assert_eq!(z_q_WV.len(), self.V.len());

    let mut A_terms = Vec::with_capacity(1 + (3 * y_n.len()) + self.V.len() + 1);
    A_terms.push((C::F::ONE, MultiexpPoint::Variable(A)));
    for (i, scalar) in WR_y_z.0.iter().enumerate() {
      A_terms.push((*scalar, self.generators.generator(GeneratorsList::GBold1, i).clone()));
    }
    for (i, scalar) in WL_y_z.0.iter().enumerate() {
      A_terms.push((*scalar, self.generators.generator(GeneratorsList::HBold1, i).clone()));
    }

    for (i, scalar) in WO_y_z.0.iter().enumerate() {
      A_terms.push((
        (*scalar - C::F::ONE) * inv_y_n.0.last().unwrap(),
        self.generators.generator(GeneratorsList::HBold2, i).clone(),
      ));
    }
    let neg_inv_y_n = -*inv_y_n.0.last().unwrap();
    for i in WO_y_z.len() .. inv_y_n.len() {
      A_terms.push((neg_inv_y_n, self.generators.generator(GeneratorsList::HBold2, i).clone()));
    }

    for pair in z_q_WV.0.iter().zip(self.V.0.iter()) {
      A_terms.push((*pair.0, MultiexpPoint::Variable(*pair.1)));
    }
    let y_n = ScalarVector(y_n);

    let mut w_WL = WL_y_z.clone();
    for (i, w) in w_WL.0.iter_mut().enumerate() {
      *w *= y_n.0[i];
    }
    A_terms.push((
      z_q.inner_product(&self.c) + WR_y_z.inner_product(&w_WL),
      self.generators.g().clone(),
    ));

    (y_n, inv_y_n.0, z_q_WV, WL_y_z, WR_y_z, WO_y_z, A_terms)
  }

  pub fn prove_with_blind<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    transcript: &mut T,
    mut witness: ArithmeticCircuitWitness<C>,
    blind: C::F,
  ) -> ArithmeticCircuitProof<C> {
    let m = self.V.len();

    assert_eq!(m, witness.v.len());
    assert_eq!(m, witness.gamma.len());

    for (commitment, (value, gamma)) in
      self.V.0.iter().zip(witness.v.0.iter().zip(witness.gamma.0.iter()))
    {
      assert_eq!(
        *commitment,
        multiexp(&[(*value, self.generators.g().point()), (*gamma, self.generators.h().point())])
      );
    }

    // aL * aR = aO doesn't need checking since we generate aO ourselves on witness creation
    debug_assert_eq!(witness.aL.len(), witness.aR.len());

    // TODO: Check WL WR WO WV

    self.initial_transcript(transcript);

    let alpha = blind;
    let mut A_terms = Vec::with_capacity((witness.aL.len() * 3) + 1);
    for (i, aL) in witness.aL.0.iter().enumerate() {
      A_terms.push((*aL, self.generators.generator(GeneratorsList::GBold1, i).point()));
    }
    for (i, aR) in witness.aR.0.iter().enumerate() {
      A_terms.push((*aR, self.generators.generator(GeneratorsList::HBold1, i).point()));
    }
    for (i, aO) in witness.aO.0.iter().enumerate() {
      A_terms.push((*aO, self.generators.generator(GeneratorsList::GBold2, i).point()));
    }
    A_terms.push((alpha, self.generators.h().point()));
    let A = multiexp(&A_terms);
    A_terms.zeroize();

    let (y_n, inv_y_n, z_q_WV, WL_y_z, WR_y_z, WO_y_z, A_hat) = self.compute_A_hat(transcript, A);

    let mut aL = witness.aL.add_vec(&WR_y_z);
    let mut aR = witness.aR.add_vec(&WL_y_z);
    let pow_2 = padded_pow_of_2(aL.len());
    aL.0.reserve(2 * pow_2);
    aR.0.reserve(2 * pow_2);
    while aL.len() < pow_2 {
      aL.0.push(C::F::ZERO);
      aR.0.push(C::F::ZERO);
    }

    aL.0.append(&mut witness.aO.0);
    for o in WO_y_z.0 {
      aR.0.push((o - C::F::ONE) * inv_y_n.last().unwrap());
    }

    let neg_inv_y_n = -*inv_y_n.last().unwrap();
    while aR.len() < (2 * pow_2) {
      aL.0.push(C::F::ZERO);
      aR.0.push(neg_inv_y_n);
    }

    let alpha = alpha + z_q_WV.inner_product(&witness.gamma);

    // Safe to not transcript A_hat since A_hat is solely derivative of transcripted values
    ArithmeticCircuitProof {
      A,
      wip: WipStatement::new_without_P_transcript(
        &self.generators.reduce(self.WL.width(), true),
        A_hat,
        y_n,
        inv_y_n,
      )
      .prove(rng, transcript, WipWitness::new(aL, aR, alpha)),
    }
  }

  pub fn prove<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    transcript: &mut T,
    witness: ArithmeticCircuitWitness<C>,
  ) -> ArithmeticCircuitProof<C> {
    let blind = C::F::random(&mut *rng);
    self.prove_with_blind(rng, transcript, witness, blind)
  }

  pub fn verify<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    verifier: &mut BatchVerifier<(), C::G>,
    transcript: &mut T,
    proof: ArithmeticCircuitProof<C>,
  ) {
    self.initial_transcript(transcript);

    let (y_n, inv_y_n, _, _, _, _, A_hat) = self.compute_A_hat(transcript, proof.A);
    let reduced = self.generators.reduce(self.WL.width(), true);
    (WipStatement::new_without_P_transcript(&reduced, A_hat, y_n, inv_y_n))
      .verify(rng, verifier, transcript, proof.wip);
  }
}
